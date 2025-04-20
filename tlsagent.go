package main

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

func LookupIP(addr string) (net.IP, error) {
	ips, err := net.LookupIP(addr)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup: %w", err)
	}

	var arr []net.IP
	for _, ip := range ips {
		if ip.To4() != nil {
			arr = append(arr, ip)
		}
	}

	if len(arr) == 0 {
		return nil, fmt.Errorf("no lookup ip addresses found: %s", addr)
	}

	return arr[0], nil
}

func NextIP(ip net.IP, increment bool) net.IP {
	ipb := big.NewInt(0).SetBytes(ip)
	if increment {
		ipb.Add(ipb, big.NewInt(1))
	} else {
		ipb.Sub(ipb, big.NewInt(1))
	}

	// Add leading zeros
	b := ipb.Bytes()
	b = append(make([]byte, len(ip)-len(b)), b...)
	return b
}

func AccumulateHost(origin string, port int, depth int) <-chan Host {
	hostChan := make(chan Host)

	_, _, err := net.ParseCIDR(origin)
	if err == nil {
		// Origin is CIDR
		slog.Error("Origin is CIDR", "origin", origin)
		p, err := netip.ParsePrefix(origin)
		if err != nil {
			slog.Warn("Invalid CIDR", "cidr", origin, "err", err)
		}
		if !p.Addr().Is4() {
			return nil
		}
		p = p.Masked()
		addr := p.Addr()
		for {
			if !p.Contains(addr) {
				break
			}
			ip := net.ParseIP(addr.String())
			if ip != nil {
				hostChan <- Host{
					IP:     ip,
					Port:   port,
					Origin: origin,
				}
			}
			addr = addr.Next()
		}
	}

	ip := net.ParseIP(origin)
	if ip == nil {
		ip, err = LookupIP(origin)
		if err != nil {
			close(hostChan)
			slog.Error("Not a valid IP, IP CIDR or domain", "origin", origin)
			return nil
		}
	}

	go func() {
		slog.Info("Host accumalating with depth", "depth", depth)
		lowIP := ip
		highIP := ip
		hostChan <- Host{
			IP:     ip,
			Port:   port,
			Origin: origin,
		}

		for i := range depth {
			if i%2 == 0 {
				lowIP = NextIP(lowIP, false)
				hostChan <- Host{
					IP:     lowIP,
					Port:   port,
					Origin: lowIP.String(),
				}
			} else {
				highIP = NextIP(highIP, true)
				hostChan <- Host{
					IP:     highIP,
					Port:   port,
					Origin: highIP.String(),
				}
			}
		}
		close(hostChan)
	}()

	return hostChan
}

func TlsScan(host Host, timeout int) (map[string]any, error) {
	if host.IP == nil {
		slog.Debug("TLS trying to lookup ip")
		ip, err := LookupIP(host.Origin)
		if err != nil {
			slog.Error("Failed to get ip from origin", "origin", host.Origin, "error", err)
			return nil, err
		}
		host.IP = ip
	}
	hostPort := net.JoinHostPort(host.IP.String(), strconv.Itoa(host.Port))

	slog.Debug("TLS setting dialtimeout", "host_port", hostPort)
	conn, err := net.DialTimeout("tcp", hostPort, time.Duration(timeout)*time.Second)
	if err != nil {
		slog.Error("Could not dial to target", "host_port", hostPort)
		return nil, err
	}

	slog.Debug("TLS setting deadline")
	defer conn.Close()
	err = conn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
	if err != nil {
		slog.Error("Error setting deadline", "error", err)
		return nil, err
	}

	tlsCfg := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
		CurvePreferences:   []tls.CurveID{tls.X25519},
	}

	// Host is domain
	if host.IP == nil {
		slog.Debug("TLS host is domain")
		tlsCfg.ServerName = host.Origin
	}

	slog.Debug("TLS tries to get handshake")
	c := tls.Client(conn, tlsCfg)
	err = c.Handshake()
	if err != nil {
		slog.Debug("TLS client handshake error", "error", err)
		return nil, err
	}

	state := c.ConnectionState()
	alpn := state.NegotiatedProtocol
	domain := state.PeerCertificates[0].Subject.CommonName
	issuers := strings.Join(state.PeerCertificates[0].Issuer.Organization, " | ")
	feasible := true
	// geoCode := geo.GetGeo(host.IP)

	if state.Version != tls.VersionTLS13 || alpn != "h2" || len(domain) == 0 || len(issuers) == 0 {
		slog.Warn("TLS host is not feasible", "host_port", hostPort, "domain", domain)
		feasible = false
		result := map[string]any{
			"ip":       host.IP.String(),
			"host":     host.Origin,
			"domain":   domain,
			"issuers":  issuers,
			"version":  state.Version,
			"alpn":     alpn,
			"feasible": feasible,
		}
		return result, nil
	} else {
		result := map[string]any{
			"ip":       host.IP.String(),
			"host":     host.Origin,
			"domain":   domain,
			"issuers":  issuers,
			"version":  state.Version,
			"alpn":     alpn,
			"feasible": feasible,
		}
		return result, nil
	}
}

type TLSAgent struct {
	BaseAgent
}

func NewTCPAgent(appState *AppState) *TLSAgent {
	return &TLSAgent{
		BaseAgent: BaseAgent{
			ID:       "tls",
			AppState: appState,
		},
	}
}

func (ta *TLSAgent) Run(interval int) {
	slog.Info("Starting TLS scanner agent and listening for tasks")

	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	for {
		if ta.AppState.Stop {
			slog.Debug("Stopping TLS agent")
			break
		}

		taskChan := ta.AppState.GetChanTask("tls")
		if taskChan == nil {
			slog.Debug("TLS channel not initialized yet, waiting")
			<-ticker.C
			continue
		}

		select {
		case task, ok := <-taskChan:
			if !ok {
				slog.Debug("TLS channel closed")
				return
			}

			slog.Debug("TLS agent received task", "task", task)
			slog.Info("TLS agent starts processing task, please stand by")
			ta.AppState.SetAgentOutput(ta.ID, AgentStatusRunning, nil)

			hostChan := AccumulateHost(task.Host.Origin, task.Host.Port, task.Depth)

			go func() {
				for host := range hostChan {
					slog.Debug("TLS scan host", "host", host)
					result, err := TlsScan(host, task.Timeout)
					if err == nil {
						ta.AppState.SetAgentOutput(ta.ID, AgentStatusCompleted, result)
						ta.AppState.AddChanTask("ping", ScanTask{
							Type:    "ping",
							Host:    host,
							Timeout: task.Timeout,
							Depth:   task.Depth,
						})
					}
				}

				slog.Info("TLS agent finished work. Press Ctrl + C to stop agents")
			}()
		case <-ticker.C:
			slog.Debug("Tls agent no tasks available, waiting")
		}
	}
}
