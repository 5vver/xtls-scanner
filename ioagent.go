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

type ScanTask struct {
	SNIEnabled bool
	TCPEnabled bool
	URLEnabled bool
	Host       string
	Port       int
	Timeout    int
}

type IOAgent struct {
	BaseAgent
	taskChan chan ScanTask
}

func NewIOAgent(appState *AppState, taskChan chan ScanTask) *IOAgent {
	return &IOAgent{
		BaseAgent: BaseAgent{
			ID:       "io-supervisor",
			AppState: appState,
			TaskChan: taskChan,
		},
		taskChan: taskChan,
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

func (io *IOAgent) ParseArguments() (ScanTask, error) {
	sni := flag.Bool("sni", false, "Enable SNI scanning")
	tcp := flag.Bool("tcp", false, "Enable TCP port scanning")
	url := flag.Bool("url", false, "Enable URL scanning")
	host := flag.String("host", "", "Target IP, CIDR or hostname")
	port := flag.Int("port", 443, "Target port")
	timeout := flag.Int("timeout", 10, "Scan timeout")

	flag.Parse()

	if *host == "" {
		return ScanTask{}, fmt.Errorf("host is required")
	}

	if !*sni && !*tcp && !*url {
		return ScanTask{}, fmt.Errorf("at least one scan type (-sni, -tcp, -url) must be enabled")
	}

	parsedHost, err := ParseHost(*host, *port)
	if err != nil {
		return ScanTask{}, err
	}
	log.Println(parsedHost)

	io.AppState.SetTask("sni", *sni)
	io.AppState.SetTask("tcp", *tcp)
	io.AppState.SetTask("url", *url)
	io.AppState.SetHost(parsedHost)
	io.AppState.SetTimeout(*timeout)

	return ScanTask{
		SNIEnabled: *sni,
		TCPEnabled: *tcp,
		URLEnabled: *url,
		Host:       *host,
		Port:       *port,
		Timeout:    *timeout,
	}, nil
}

func (io *IOAgent) Run() {
	log.Printf("Starting I/O Supervisor Agent (%s)", io.ID)

	task, err := io.ParseArguments()
	if err != nil {
		log.Printf("Error parsing arguments: %v", err)
		io.AppState.SetAgentOutput(io.ID, AgentStatusFailed, map[string]interface{}{"error": err.Error()})
		return
	}

	io.AppState.SetAgentOutput(io.ID, AgentStatusRunning, nil)

	log.Printf("Scheduling task for host: %s, SNI: %v, TCP: %v, URL: %v",
		task.Host, task.SNIEnabled, task.TCPEnabled, task.URLEnabled)
	io.taskChan <- task

	io.AppState.SetAgentOutput(io.ID, AgentStatusCompleted, map[string]interface{}{
		"host": task.Host,
		"tasks": map[string]bool{
			"sni": task.SNIEnabled,
			"tcp": task.TCPEnabled,
			"url": task.URLEnabled,
		},
	})

	close(io.taskChan)
}
