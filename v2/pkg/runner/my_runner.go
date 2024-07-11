package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/blackrock"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/mapcidr"
	"github.com/projectdiscovery/ratelimit"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/projectdiscovery/uncover/sources/agent/shodanidb"
	"github.com/remeh/sizedwaitgroup"
	"github.com/secoba/naabu/v2/pkg/port"
	"github.com/secoba/naabu/v2/pkg/privileges"
	"github.com/secoba/naabu/v2/pkg/protocol"
	"github.com/secoba/naabu/v2/pkg/result"
	"github.com/secoba/naabu/v2/pkg/scan"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"
)

func (r *Runner) Close2() {
	defer func() {
		if e := recover(); e != nil {
			fmt.Println(e)
		}
	}()
	_ = os.RemoveAll(r.targetsFile)
	_ = r.scanner.IPRanger.Hosts.Close()
	if r.options.EnableProgressBar {
		_ = r.stats.Stop()
	}
	if r.scanner != nil {
		r.scanner.Close2()
	}
	if r.limiter != nil {
		r.limiter.Stop()
	}
}

func (r *Runner) handleHostPort2(ctx context.Context, host string, p *port.Port) {
	defer r.wgscan.Done()

	select {
	case <-ctx.Done():
		return
	default:
		// performs cdn scan exclusions checks
		if !r.canIScanIfCDN(host, p) {
			gologger.Debug().Msgf("Skipping cdn target: %s:%d\n", host, p.Port)
			return
		}

		if r.scanner.ScanResults.IPHasPort(host, p) {
			return
		}

		r.limiter.Take()
		open, err := r.scanner.ConnectPort2(host, p, time.Duration(r.options.Timeout)*time.Millisecond)
		if open && err == nil {
			r.scanner.ScanResults.AddPort(host, p)
			if r.scanner.OnReceive != nil {
				r.scanner.OnReceive(&result.HostResult{IP: host, Ports: []*port.Port{p}})
			}
		}
	}
}

// RunEnumeration2 runs the ports enumeration flow on the targets specified
func (r *Runner) RunEnumeration2(pctx context.Context) error {
	ctx, cancel := context.WithCancel(pctx)
	defer cancel()

	if r.scanner == nil || r.scanner.ListenHandler == nil {
		return errors.New("closed2")
	}

	if privileges.IsPrivileged && r.options.ScanType == SynScan {
		// Set values if those were specified via cli, errors are fatal
		if r.options.SourceIP != "" {
			err := r.SetSourceIP(r.options.SourceIP)
			if err != nil {
				return err
			}
		}
		if r.options.Interface != "" {
			err := r.SetInterface(r.options.Interface)
			if err != nil {
				return err
			}
		}
		if r.options.SourcePort != "" {
			err := r.SetSourcePort(r.options.SourcePort)
			if err != nil {
				return err
			}
		}
		r.BackgroundWorkers(ctx)
	}

	if r.options.Stream {
		go r.Load() //nolint
	} else {
		err := r.Load()
		if err != nil {
			return err
		}
	}

	// Scan workers
	r.wgscan = sizedwaitgroup.New(r.options.Rate)
	r.limiter = ratelimit.New(context.Background(), uint(r.options.Rate), time.Second)

	shouldDiscoverHosts := r.options.shouldDiscoverHosts()
	shouldUseRawPackets := r.options.shouldUseRawPackets()

	if shouldDiscoverHosts && shouldUseRawPackets {
		// perform host discovery
		showHostDiscoveryInfo()
		if r.scanner == nil || r.scanner.ListenHandler == nil {
			return errors.New("closed2")
		}
		r.scanner.ListenHandler.Phase.Set(scan.HostDiscovery)
		// shrinks the ips to the minimum amount of cidr
		_, targetsV4, targetsv6, _, err := r.GetTargetIps(r.getPreprocessedIps)
		if err != nil {
			return err
		}

		// get excluded ips
		excludedIPs, err := r.parseExcludedIps(r.options)
		if err != nil {
			return err
		}

		// store exclued ips to a map
		excludedIPsMap := make(map[string]struct{})
		for _, ipString := range excludedIPs {
			excludedIPsMap[ipString] = struct{}{}
		}

		discoverCidr := func(cidr *net.IPNet) {
			ipStream, _ := mapcidr.IPAddressesAsStream(cidr.String())
			for ip := range ipStream {
				// only run host discovery if the ip is not present in the excludedIPsMap
				if _, exists := excludedIPsMap[ip]; !exists {
					r.handleHostDiscovery(ip)
				}
			}
		}

		for _, target4 := range targetsV4 {
			discoverCidr(target4)
		}
		for _, target6 := range targetsv6 {
			discoverCidr(target6)
		}

		if r.options.WarmUpTime > 0 {
			time.Sleep(time.Duration(r.options.WarmUpTime) * time.Second)
		}

		// check if we should stop here or continue with full scan
		if r.options.OnlyHostDiscovery {
			r.handleOutput(r.scanner.HostDiscoveryResults)
			return nil
		}
	}

	switch {
	case r.options.Stream && !r.options.Passive: // stream active
		showNetworkCapabilities(r.options)
		if r.scanner == nil || r.scanner.ListenHandler == nil {
			return errors.New("closed2")
		}
		r.scanner.ListenHandler.Phase.Set(scan.Scan)

		handleStreamIp := func(target string, port *port.Port) bool {
			if r.scanner.ScanResults.HasSkipped(target) {
				return false
			}
			if r.options.PortThreshold > 0 && r.scanner.ScanResults.GetPortCount(target) >= r.options.PortThreshold {
				hosts, _ := r.scanner.IPRanger.GetHostsByIP(target)
				gologger.Info().Msgf("Skipping %s %v, Threshold reached \n", target, hosts)
				r.scanner.ScanResults.AddSkipped(target)
				return false
			}
			if shouldUseRawPackets {
				r.RawSocketEnumeration(ctx, target, port)
			} else {
				r.wgscan.Add()
				go r.handleHostPort(ctx, target, port)
			}
			return true
		}

		for target := range r.streamChannel {
			if err := r.scanner.IPRanger.Add(target.Cidr); err != nil {
				gologger.Warning().Msgf("Couldn't track %s in scan results: %s\n", target, err)
			}
			if ipStream, err := mapcidr.IPAddressesAsStream(target.Cidr); err == nil {
				for ip := range ipStream {
					for _, port := range r.scanner.Ports {
						if !handleStreamIp(ip, port) {
							break
						}
					}
				}
			} else if target.Ip != "" && target.Port != "" {
				pp, _ := strconv.Atoi(target.Port)
				handleStreamIp(target.Ip, &port.Port{Port: pp, Protocol: protocol.TCP})
			}
		}
		r.wgscan.Wait()
		r.handleOutput(r.scanner.ScanResults)
		return nil
	case r.options.Stream && r.options.Passive: // stream passive
		showNetworkCapabilities(r.options)
		// create retryablehttp instance
		httpClient := retryablehttp.NewClient(retryablehttp.DefaultOptionsSingle)
		if r.scanner == nil || r.scanner.ListenHandler == nil {
			return errors.New("closed2")
		}
		r.scanner.ListenHandler.Phase.Set(scan.Scan)
		for target := range r.streamChannel {
			if err := r.scanner.IPRanger.Add(target.Cidr); err != nil {
				gologger.Warning().Msgf("Couldn't track %s in scan results: %s\n", target, err)
			}
			ipStream, _ := mapcidr.IPAddressesAsStream(target.Cidr)
			for ip := range ipStream {
				r.wgscan.Add()
				go func(ip string) {
					defer r.wgscan.Done()

					// obtain ports from shodan idb
					shodanURL := fmt.Sprintf(shodanidb.URL, url.QueryEscape(ip))
					request, err := retryablehttp.NewRequest(http.MethodGet, shodanURL, nil)
					if err != nil {
						gologger.Warning().Msgf("Couldn't create http request for %s: %s\n", ip, err)
						return
					}
					r.limiter.Take()
					response, err := httpClient.Do(request)
					if err != nil {
						gologger.Warning().Msgf("Couldn't retrieve http response for %s: %s\n", ip, err)
						return
					}
					if response.StatusCode != http.StatusOK {
						gologger.Warning().Msgf("Couldn't retrieve data for %s, server replied with status code: %d\n", ip, response.StatusCode)
						return
					}

					// unmarshal the response
					data := &shodanidb.ShodanResponse{}
					if err := json.NewDecoder(response.Body).Decode(data); err != nil {
						gologger.Warning().Msgf("Couldn't unmarshal json data for %s: %s\n", ip, err)
						return
					}

					var passivePorts []*port.Port
					for _, p := range data.Ports {
						pp := &port.Port{Port: p, Protocol: protocol.TCP}
						passivePorts = append(passivePorts, pp)
					}

					filteredPorts, err := excludePorts(r.options, passivePorts)
					if err != nil {
						gologger.Warning().Msgf("Couldn't exclude ports for %s: %s\n", ip, err)
						return
					}
					for _, p := range filteredPorts {
						if r.scanner.OnReceive != nil {
							r.scanner.OnReceive(&result.HostResult{IP: ip, Ports: []*port.Port{p}})
						}
						r.scanner.ScanResults.AddPort(ip, p)
					}
				}(ip)
			}
		}
		r.wgscan.Wait()

		// Validate the hosts if the user has asked for second step validation
		if r.options.Verify {
			r.ConnectVerification()
		}

		r.handleOutput(r.scanner.ScanResults)

		// handle nmap
		return r.handleNmap()
	default:
		showNetworkCapabilities(r.options)

		ipsCallback := r.getPreprocessedIps
		if shouldDiscoverHosts && shouldUseRawPackets {
			ipsCallback = r.getHostDiscoveryIps
		}

		// shrinks the ips to the minimum amount of cidr
		targets, targetsV4, targetsv6, targetsWithPort, err := r.GetTargetIps(ipsCallback)
		if err != nil {
			return err
		}
		var targetsCount, portsCount, targetsWithPortCount uint64
		for _, target := range append(targetsV4, targetsv6...) {
			if target == nil {
				continue
			}
			targetsCount += mapcidr.AddressCountIpnet(target)
		}
		portsCount = uint64(len(r.scanner.Ports))
		targetsWithPortCount = uint64(len(targetsWithPort))

		if r.scanner == nil || r.scanner.ListenHandler == nil {
			return errors.New("closed2")
		}

		r.scanner.ListenHandler.Phase.Set(scan.Scan)
		Range := targetsCount * portsCount
		if r.options.EnableProgressBar {
			r.stats.AddStatic("ports", portsCount)
			r.stats.AddStatic("hosts", targetsCount)
			r.stats.AddStatic("retries", r.options.Retries)
			r.stats.AddStatic("startedAt", time.Now())
			r.stats.AddCounter("packets", uint64(0))
			r.stats.AddCounter("errors", uint64(0))
			r.stats.AddCounter("total", Range*uint64(r.options.Retries)+targetsWithPortCount)
			r.stats.AddStatic("hosts_with_port", targetsWithPortCount)
			if err := r.stats.Start(); err != nil {
				gologger.Warning().Msgf("Couldn't start statistics: %s\n", err)
			}
		}

		// Retries are performed regardless of the previous scan results due to network unreliability
		for currentRetry := 0; currentRetry < r.options.Retries; currentRetry++ {
			if currentRetry < r.options.ResumeCfg.Retry {
				gologger.Debug().Msgf("Skipping Retry: %d\n", currentRetry)
				continue
			}

			// Use current time as seed
			currentSeed := time.Now().UnixNano()
			r.options.ResumeCfg.RLock()
			if r.options.ResumeCfg.Seed > 0 {
				currentSeed = r.options.ResumeCfg.Seed
			}
			r.options.ResumeCfg.RUnlock()

			// keep track of current retry and seed for resume
			r.options.ResumeCfg.Lock()
			r.options.ResumeCfg.Retry = currentRetry
			r.options.ResumeCfg.Seed = currentSeed
			r.options.ResumeCfg.Unlock()

			b := blackrock.New(int64(Range), currentSeed)
			for index := int64(0); index < int64(Range); index++ {
				xxx := b.Shuffle(index)
				ipIndex := xxx / int64(portsCount)
				portIndex := int(xxx % int64(portsCount))
				ip := r.PickIP(targets, ipIndex)
				port := r.PickPort(portIndex)

				r.options.ResumeCfg.RLock()
				resumeCfgIndex := r.options.ResumeCfg.Index
				r.options.ResumeCfg.RUnlock()
				if index < resumeCfgIndex {
					gologger.Debug().Msgf("Skipping \"%s:%d\": Resume - Port scan already completed\n", ip, port.Port)
					continue
				}

				r.limiter.Take()
				//resume cfg logic
				r.options.ResumeCfg.Lock()
				r.options.ResumeCfg.Index = index
				r.options.ResumeCfg.Unlock()

				if r.scanner.ScanResults.HasSkipped(ip) {
					continue
				}
				if r.options.PortThreshold > 0 && r.scanner.ScanResults.GetPortCount(ip) >= r.options.PortThreshold {
					hosts, _ := r.scanner.IPRanger.GetHostsByIP(ip)
					gologger.Info().Msgf("Skipping %s %v, Threshold reached \n", ip, hosts)
					r.scanner.ScanResults.AddSkipped(ip)
					continue
				}

				// connect scan
				if shouldUseRawPackets {
					r.RawSocketEnumeration(ctx, ip, port)
				} else {
					r.wgscan.Add()
					go r.handleHostPort2(ctx, ip, port)
				}
				if r.options.EnableProgressBar {
					r.stats.IncrementCounter("packets", 1)
				}
			}

			// handle the ip:port combination
			for _, targetWithPort := range targetsWithPort {
				ip, p, err := net.SplitHostPort(targetWithPort)
				if err != nil {
					gologger.Debug().Msgf("Skipping %s: %v\n", targetWithPort, err)
					continue
				}

				// naive port find
				pp, err := strconv.Atoi(p)
				if err != nil {
					gologger.Debug().Msgf("Skipping %s, could not cast port %s: %v\n", targetWithPort, p, err)
					continue
				}
				var portWithMetadata = port.Port{
					Port:     pp,
					Protocol: protocol.TCP,
				}

				// connect scan
				if shouldUseRawPackets {
					r.RawSocketEnumeration(ctx, ip, &portWithMetadata)
				} else {
					r.wgscan.Add()
					go r.handleHostPort(ctx, ip, &portWithMetadata)
				}
				if r.options.EnableProgressBar {
					r.stats.IncrementCounter("packets", 1)
				}
			}

			r.wgscan.Wait()

			r.options.ResumeCfg.Lock()
			if r.options.ResumeCfg.Seed > 0 {
				r.options.ResumeCfg.Seed = 0
			}
			if r.options.ResumeCfg.Index > 0 {
				// zero also the current index as we are restarting the scan
				r.options.ResumeCfg.Index = 0
			}
			r.options.ResumeCfg.Unlock()
		}

		if r.options.WarmUpTime > 0 {
			time.Sleep(time.Duration(r.options.WarmUpTime) * time.Second)
		}

		if r.scanner == nil || r.scanner.ListenHandler == nil {
			return errors.New("closed2")
		}

		r.scanner.ListenHandler.Phase.Set(scan.Done)

		// Validate the hosts if the user has asked for second step validation
		if r.options.Verify {
			r.ConnectVerification()
		}

		r.handleOutput(r.scanner.ScanResults)

		// handle nmap
		return r.handleNmap()
	}
}
