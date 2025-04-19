package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"log/slog"
	"net"
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
				slog.Debug("TLS channel not initialized yet, waiting")
				return
			}

			slog.Debug("TLS agent received task", "task", task)
			slog.Info("TLS agent starts processing task, please stand by")

			ta.AppState.SetAgentOutput(ta.ID, AgentStatusRunning, nil)
			host := task.Host
			t := time.Now()

			if host.IP == nil {
				slog.Debug("TLS trying to lookup ip")
				ip, err := LookupIP(host.Origin)
				if err != nil {
					ta.AppState.SetAgentOutput(ta.ID, AgentStatusFailed, nil)
					slog.Error("Failed to get ip from origin", "origin", host.Origin, "error", err)
					return
				}
				host.IP = ip
			}

			hostPort := net.JoinHostPort(host.IP.String(), strconv.Itoa(host.Port))
			slog.Debug("TLS setting dialtimeout", "host_port", hostPort)
			conn, err := net.DialTimeout("tcp", hostPort, time.Duration(ta.AppState.Timeout)*time.Second)
			if err != nil {
				ta.AppState.SetAgentOutput(ta.ID, AgentStatusFailed, nil)
				slog.Error("Could not dial to target", "host_port", hostPort)
				return
			}

			slog.Debug("TLS setting deadline")
			defer conn.Close()
			err = conn.SetDeadline(time.Now().Add(time.Duration(ta.AppState.Timeout) * time.Second))
			if err != nil {
				ta.AppState.SetAgentOutput(ta.ID, AgentStatusFailed, nil)
				slog.Error("Error setting deadline", "error", err)
				return
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
			log.Println(c.ConnectionState())
			err = c.Handshake()
			if err != nil {
				slog.Debug("TLS client handshake error", "error", err)
				ta.AppState.SetAgentOutput(ta.ID, AgentStatusFailed, nil)
				return
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
				ta.AppState.SetAgentOutput(ta.ID, AgentStatusCompleted,
					map[string]any{
						"elapsed":  time.Since(t).String(),
						"feasible": feasible,
						"result":   "not feasible",
					},
				)
			} else {
				result := map[string]any{
					"elapsed":  time.Since(t).String(),
					"ip":       host.IP.String(),
					"host":     host.Origin,
					"domain":   domain,
					"issuers":  issuers,
					"feasible": feasible,
					"result":   fmt.Sprintf("%s scan completed", "sni"),
				}
				ta.AppState.SetAgentOutput(ta.ID, AgentStatusCompleted, result)
			}
			slog.Info("TLS agent finished work")
		}
	}
}
