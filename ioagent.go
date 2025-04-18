package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"regexp"
	"strings"
)

type Arguments struct {
	SNIEnabled  bool
	TLSEnabled  bool
	PingEnabled bool
	Host        Host
	Timeout     int
}

type IOAgent struct {
	BaseAgent
}

func NewIOAgent(appState *AppState) *IOAgent {
	return &IOAgent{
		BaseAgent: BaseAgent{
			ID:       "io-supervisor",
			AppState: appState,
		},
	}
}

func ParseHost(hostValue string, port int) (Host, error) {
	host := strings.TrimSpace(hostValue)
	if host == "" {
		return Host{}, fmt.Errorf("Host must not be empty")
	}

	// Try parse ip
	ip := net.ParseIP(host)
	if ip != nil && (ip.To4() != nil) {
		return Host{
			IP:     ip,
			Origin: host,
			Port:   port,
		}, nil
	}

	// Try parse CIDR
	_, _, err := net.ParseCIDR(hostValue)
	if err == nil {
		// ip cidr
		p, err := netip.ParsePrefix(hostValue)
		if err != nil {
			return Host{}, fmt.Errorf("Invalid CIDR %s", host)
		}
		p = p.Masked()
		addr := p.Addr()
		for {
			if !p.Contains(addr) {
				break
			}
			ip = net.ParseIP(addr.String())
			if ip != nil {
				return Host{
					IP:     ip,
					Origin: host,
					Port:   port,
				}, nil
			}
			addr = addr.Next()
		}
	}

	// Try parse domain
	r := regexp.MustCompile(`(?m)^[A-Za-z0-9\-.]+$`)
	if r.MatchString(host) {
		return Host{
			IP:     nil,
			Origin: host,
			Port:   port,
		}, nil
	}

	return Host{}, fmt.Errorf("host is not valid ip, cidr or domain: %s", host)
}

func ParseArguments() (Arguments, error) {
	sni := flag.Bool("sni", false, "Enable SNI scanning")
	tls := flag.Bool("tls", false, "Enable TLS host scanning")
	ping := flag.Bool("ping", false, "Enable Ping scanning")
	host := flag.String("host", "", "Target IP, CIDR or hostname")
	port := flag.Int("port", 443, "Target port")
	timeout := flag.Int("timeout", 10, "Scan timeout")

	flag.Parse()

	if *host == "" {
		return Arguments{}, fmt.Errorf("host is required")
	}

	if !*sni && !*tls && !*ping {
		return Arguments{}, fmt.Errorf("at least one scan type (-sni, -tls, -ping) must be enabled")
	}

	parsedHost, err := ParseHost(*host, *port)
	if err != nil {
		return Arguments{}, err
	}

	return Arguments{
		SNIEnabled:  *sni,
		TLSEnabled:  *tls,
		PingEnabled: *ping,
		Host:        parsedHost,
		Timeout:     *timeout,
	}, nil
}

func (io *IOAgent) Run() {
	log.Printf("Starting I/O Supervisor Agent (%s)", io.ID)
	io.AppState.SetAgentOutput(io.ID, AgentStatusRunning, nil)

	args, err := ParseArguments()
	if err != nil {
		log.Printf("Error parsing arguments: %v", err)
		io.AppState.SetAgentOutput(io.ID, AgentStatusFailed, map[string]any{"error": err.Error()})
		return
	}

	log.Printf("Scheduling task for host: %s, SNI: %v, TCP: %v, Ping: %v",
		args.Host.Origin, args.SNIEnabled, args.TLSEnabled, args.PingEnabled)

	if args.PingEnabled {
		log.Println("Creating and adding task for ping agent")
		task := ScanTask{
			Type:    "ping",
			Host:    args.Host,
			Timeout: args.Timeout,
		}
		io.AppState.AddChanTask("ping", task)
	}
	if args.TLSEnabled {
		task := ScanTask{
			Type:    "tls",
			Host:    args.Host,
			Timeout: args.Timeout,
		}
		io.AppState.AddChanTask("tls", task)
	}
	if args.SNIEnabled {
		task := ScanTask{
			Type:    "sni",
			Host:    args.Host,
			Timeout: args.Timeout,
		}
		io.AppState.AddChanTask("sni", task)
	}

	io.AppState.SetAgentOutput(io.ID, AgentStatusCompleted, map[string]any{
		"host": args.Host,
		"tasks": map[string]bool{
			"sni":  args.SNIEnabled,
			"tcp":  args.TLSEnabled,
			"ping": args.PingEnabled,
		},
	})
}
