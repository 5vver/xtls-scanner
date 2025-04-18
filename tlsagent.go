package main

import (
	"crypto/tls"
	"fmt"
	"log"
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
	log.Printf("Starting %s Scanner Agent", ta.ID)

	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	for {
		if ta.AppState.Stop {
			log.Println("[TLS] stopping")
			break
		}

		taskChan := ta.AppState.GetChanTask("tls")
		if taskChan == nil {
			log.Println("TLS channel not initialized yet, waiting...")
			<-ticker.C
			continue
		}

		select {
		case task, ok := <-taskChan:
			if !ok {
				log.Println("Task channel closed, stopping agent")
				return
			}

			log.Println("Received task:", task)

			ta.AppState.SetAgentOutput(ta.ID, AgentStatusRunning, nil)
			host := task.Host
			t := time.Now()

			if host.IP == nil {
				// log
				log.Println("tls processing host ip")
				ip, err := LookupIP(host.Origin)
				if err != nil {
					ta.AppState.SetAgentOutput(ta.ID, AgentStatusFailed, nil)
					log.Println(fmt.Errorf("Failed to get ip from origin %s. Error: %w", host.Origin, err))
					return
				}
				host.IP = ip
			}

			hostPort := net.JoinHostPort(host.IP.String(), strconv.Itoa(host.Port))
			// log
			log.Println("tls setting dialtimeout")
			log.Println("tls hostport", hostPort)
			conn, err := net.DialTimeout("tcp", hostPort, time.Duration(ta.AppState.Timeout)*time.Second)
			if err != nil {
				ta.AppState.SetAgentOutput(ta.ID, AgentStatusFailed, nil)
				log.Println(fmt.Errorf("Could not dial to target: %s", hostPort))
				return
			}

			// log
			log.Println("tls setting deadline")
			defer conn.Close()
			err = conn.SetDeadline(time.Now().Add(time.Duration(ta.AppState.Timeout) * time.Second))
			if err != nil {
				ta.AppState.SetAgentOutput(ta.ID, AgentStatusFailed, nil)
				log.Println(fmt.Errorf("Error setting deadline %w", err))
				return
			}

			tlsCfg := &tls.Config{
				InsecureSkipVerify: true,
				NextProtos:         []string{"h2", "http/1.1"},
				CurvePreferences:   []tls.CurveID{tls.X25519},
			}

			// Host is domain
			if host.IP == nil {
				// log
				log.Println("tls host is domain")
				tlsCfg.ServerName = host.Origin
			}

			// log
			log.Println("tls client handshake")
			c := tls.Client(conn, tlsCfg)
			log.Println(c.ConnectionState())
			err = c.Handshake()
			if err != nil {
				// log
				log.Println("tcp client handshake error", fmt.Errorf("TLS handshake failed %w", err))
				ta.AppState.SetAgentOutput(ta.ID, AgentStatusFailed, nil)
				log.Println(fmt.Errorf("TLS handshake failed %w", err))
				return
			}

			state := c.ConnectionState()
			alpn := state.NegotiatedProtocol
			domain := state.PeerCertificates[0].Subject.CommonName
			issuers := strings.Join(state.PeerCertificates[0].Issuer.Organization, " | ")
			feasible := true
			// geoCode := geo.GetGeo(host.IP)

			if state.Version != tls.VersionTLS13 || alpn != "h2" || len(domain) == 0 || len(issuers) == 0 {
				// log
				log.Println("tls not feasible")
				// not feasible
				feasible = false
				ta.AppState.SetAgentOutput(ta.ID, AgentStatusCompleted,
					map[string]any{
						"elapsed":  time.Since(t).String(),
						"feasible": feasible,
						"result":   "not feasible",
					},
				)
				log.Println(
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
				// log
				log.Println("tls result", result)
				ta.AppState.SetAgentOutput(ta.ID, AgentStatusCompleted, result)
			}
		}
	}
}
