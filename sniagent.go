package main

import (
	"fmt"
	"log"
	"time"
)

type SNIAgent struct {
	BaseAgent
}

func NewSNIAgent(appState *AppState, taskChan <-chan ScanTask) *SNIAgent {
	return &SNIAgent{
		BaseAgent: BaseAgent{
			ID:       "sni-scanner",
			AppState: appState,
		},
	}
}

func (sa *SNIAgent) Run() {
	log.Printf("Starting %s Scanner Agent (%s)", "sni", sa.ID)

	task, ok := <-sa.AppState.GetChanTask("ping")
	if !ok {
		log.Println("Task channel closed")
		return
	}

	sa.AppState.SetAgentOutput(sa.ID, AgentStatusRunning, nil)

	// Simulate scanning
	log.Printf("Scanner processing host: %s", task.Host.Origin)
	time.Sleep(1 * time.Second) // Simulate work

	// Store result
	result := map[string]interface{}{
		"host":   task.Host,
		"result": fmt.Sprintf("%s scan completed", "sni"),
	}
	sa.AppState.SetAgentOutput(sa.ID, AgentStatusCompleted, result)
}
