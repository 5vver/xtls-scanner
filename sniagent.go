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
			TaskChan: taskChan,
		},
	}
}

func (sa *SNIAgent) Run() {
	log.Printf("Starting %s Scanner Agent (%s)", "sni", sa.ID)
	log.Printf("Should run sni %t", sa.AppState.ShouldExecute("sni"))

	for task := range sa.TaskChan {
		if !sa.AppState.ShouldExecute("sni") {
			continue
		}

		sa.AppState.SetAgentOutput(sa.ID, AgentStatusRunning, nil)

		// Simulate scanning
		log.Printf("%s Scanner processing host: %s", "sni", task.Host)
		time.Sleep(1 * time.Second) // Simulate work

		// Store result
		result := map[string]interface{}{
			"host":   task.Host,
			"result": fmt.Sprintf("%s scan completed", "sni"),
		}
		sa.AppState.SetAgentOutput(sa.ID, AgentStatusCompleted, result)
	}
}
