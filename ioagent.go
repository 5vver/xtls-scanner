package main

import (
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"regexp"
	"strings"
)

type Arguments struct {
	TLSEnabled  bool
	PingEnabled bool
	Host        Host
	Timeout     int
	Verbose     bool
	Depth       int
	Out         string
}

type IOAgent struct {
	BaseAgent
}

func NewIOAgent(appState *AppState) *IOAgent {
	return &IOAgent{
		BaseAgent: BaseAgent{
			ID:       "io",
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
	tls := flag.Bool("tls", false, "Enable TLS host scanning")
	ping := flag.Bool("ping", false, "Enable Ping scanning")
	host := flag.String("host", "", "Target IP, CIDR or hostname")
	port := flag.Int("port", 443, "Target port")
	timeout := flag.Int("timeout", 5, "Scan timeout")
	verbose := flag.Bool("verbose", false, "Logging verbose level messages")
	depth := flag.Int("depth", 10, "TLS ip addr crawl depth")
	out := flag.String("out", "", "Output file")

	flag.Parse()

	if *host == "" {
		return Arguments{}, fmt.Errorf("host is required")
	}

	if !*tls && !*ping {
		return Arguments{}, fmt.Errorf("at least one scan type (-sni, -tls, -ping) must be enabled")
	}

	parsedHost, err := ParseHost(*host, *port)
	if err != nil {
		return Arguments{}, err
	}

	return Arguments{
		TLSEnabled:  *tls,
		PingEnabled: *ping,
		Host:        parsedHost,
		Timeout:     *timeout,
		Verbose:     *verbose,
		Depth:       *depth,
		Out:         *out,
	}, nil
}

func FormatResult(m map[string]any) string {
	if len(m) == 0 {
		return ""
	}

	pairs := make([]string, 0, len(m))
	for k, v := range m {
		var formattedValue string
		switch val := v.(type) {
		case string:
			formattedValue = fmt.Sprintf("%q", val)
		case nil:
			formattedValue = "null"
		default:
			formattedValue = fmt.Sprintf("%v", val)
		}
		pairs = append(pairs, fmt.Sprintf("%s=%s", k, formattedValue))
	}

	return strings.Join(pairs, " ")
}

func ObserveOut(output chan AgentOutput, writer io.Writer) {
	f, isFile := writer.(*os.File)
	if isFile {
		defer f.Close()
	}

	for out := range output {
		if out.Status != AgentStatusCompleted {
			continue
		}
		slog.Info("Received output", "agent", out.ID, "result", FormatResult(out.Data))
		_, err := io.WriteString(writer, fmt.Sprintf("agent=\"%s\" %s\n", out.ID, FormatResult(out.Data)))
		if err != nil {
			slog.Error("Error writing to file", "error", err)
		}
	}
}

func (ia *IOAgent) Run() {
	slog.Info("Starting I/O agent")

	// io.AppState.SetAgentOutput(io.ID, AgentStatusRunning, nil)
	args, err := ParseArguments()
	if err != nil {
		slog.Error("Error parsing arguments", "error", err)
		ia.AppState.SetAgentOutput(ia.ID, AgentStatusFailed, map[string]any{"error": err.Error()})
		return
	}

	// Set log level
	if args.Verbose == false {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		})))
	}

	outWriter := io.Discard
	if args.Out != "" {
		slog.Debug("Setting out writer", "out", args.Out)
		f, err := os.OpenFile(args.Out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			slog.Error("Error opening file", "path", args.Out)
			return
		}
		outWriter = f
	}
	go ObserveOut(ia.AppState.OutputChan, outWriter)

	slog.Info("Scheduling tasks for host", "host", args.Host.Origin)

	if args.PingEnabled {
		slog.Debug("Creating and adding task for ping agent")
		task := ScanTask{
			Type:    "ping",
			Host:    args.Host,
			Timeout: args.Timeout,
			Depth:   args.Depth,
		}
		ia.AppState.AddChanTask("ping", task)
	}
	if args.TLSEnabled {
		slog.Debug("Creating and adding task for tls agent")
		task := ScanTask{
			Type:    "tls",
			Host:    args.Host,
			Timeout: args.Timeout,
			Depth:   args.Depth,
		}
		ia.AppState.AddChanTask("tls", task)
	}

	ia.AppState.SetAgentOutput(ia.ID, AgentStatusCompleted, map[string]any{
		"host": args.Host,
		"tasks": map[string]bool{
			"tcp":  args.TLSEnabled,
			"ping": args.PingEnabled,
		},
	})
}
