package main

import (
	"flag"
	"fmt"
	"log"
)

type ScanTask struct {
	SNIEnabled bool
	TCPEnabled bool
	URLEnabled bool
	Host       string
}

type IOAgent struct {
	BaseAgent
	taskChan chan ScanTask
}

func NewIOAgent(appState *AppState) *IOAgent {
	taskChan := make(chan ScanTask, 10)
	return &IOAgent{
		BaseAgent: BaseAgent{
			ID:       "io-supervisor",
			AppState: appState,
			TaskChan: taskChan,
		},
		taskChan: taskChan,
	}
}

func (io *IOAgent) ParseArguments() (ScanTask, error) {
	sni := flag.Bool("sni", false, "Enable SNI scanning")
	tcp := flag.Bool("tcp", false, "Enable TCP port scanning")
	url := flag.Bool("url", false, "Enable URL scanning")
	host := flag.String("host", "", "Target IP or hostname")

	flag.Parse()

	if *host == "" {
		return ScanTask{}, fmt.Errorf("host is required")
	}

	if !*sni && !*tcp && !*url {
		return ScanTask{}, fmt.Errorf("at least one scan type (-sni, -tcp, -url) must be enabled")
	}

	io.AppState.SetTask("sni", *sni)
	io.AppState.SetTask("tcp", *tcp)
	io.AppState.SetTask("url", *url)
	io.AppState.SetHost(*host)

	return ScanTask{
		SNIEnabled: *sni,
		TCPEnabled: *tcp,
		URLEnabled: *url,
		Host:       *host,
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
}
