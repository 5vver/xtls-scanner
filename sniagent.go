package main

import "log"

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
}
