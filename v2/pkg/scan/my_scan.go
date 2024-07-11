package scan

import (
	"context"
	"errors"
	"fmt"
	"github.com/secoba/naabu/v2/pkg/port"
	"github.com/secoba/naabu/v2/pkg/protocol"
	"golang.org/x/net/proxy"
	"io"
	"net"
	"os"
	"time"
)

func (s *Scanner) Close2() {
	//retries       int
	//	rate          int
	//	portThreshold int
	//	timeout       time.Duration
	//	proxyDialer   proxy.Dialer
	//
	//	Ports    []*port.Port
	//	IPRanger *ipranger.IPRanger
	//
	//	HostDiscoveryResults *result.Result
	//	ScanResults          *result.Result
	//	NetworkInterface     *net.Interface
	//	cdn                  *cdncheck.Client
	//	tcpsequencer         *TCPSequencer
	//	stream               bool
	//	ListenHandler        *ListenHandler
	//	OnReceive            result.ResultFn
	defer func() {
		if e := recover(); e != nil {
			fmt.Println(e)
		}
	}()
	s.ListenHandler.Busy = false
	s.ListenHandler = nil
}

// ConnectPort2 a single host and port
func (s *Scanner) ConnectPort2(host string, p *port.Port, timeout time.Duration) (bool, error) {
	hostport := net.JoinHostPort(host, fmt.Sprint(p.Port))
	var (
		err  error
		conn net.Conn
	)
	if s.proxyDialer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		proxyDialer, ok := s.proxyDialer.(proxy.ContextDialer)
		if !ok {
			return false, errors.New("invalid proxy dialer")
		}
		conn, err = proxyDialer.DialContext(ctx, p.Protocol.String(), hostport)
		if err != nil {
			return false, err
		}
	} else {
		netDialer := net.Dialer{
			Timeout: timeout,
		}
		if s.ListenHandler == nil {
			return false, errors.New("closed")
		}
		if s.ListenHandler.SourceIp4 != nil {
			netDialer.LocalAddr = &net.TCPAddr{IP: s.ListenHandler.SourceIp4}
		} else if s.ListenHandler.SourceIP6 != nil {
			netDialer.LocalAddr = &net.TCPAddr{IP: s.ListenHandler.SourceIP6}
		}
		conn, err = netDialer.Dial(p.Protocol.String(), hostport)
	}
	if err != nil {
		return false, err
	}
	defer conn.Close()

	// udp needs data probe
	switch p.Protocol {
	case protocol.UDP:
		if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
			return false, err
		}
		if _, err := conn.Write(nil); err != nil {
			return false, err
		}
		if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return false, err
		}
		n, err := io.Copy(io.Discard, conn)
		// ignore timeout errors
		if err != nil && !os.IsTimeout(err) {
			return false, err
		}
		return n > 0, nil
	}

	return true, err
}
