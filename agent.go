package main

type AgentStatus string

const (
	AgentStatusPending   AgentStatus = "pending"
	AgentStatusRunning   AgentStatus = "running"
	AgentStatusCompleted AgentStatus = "completed"
	AgentStatusFailed    AgentStatus = "failed"
)

type AgentOutput struct {
	Status AgentStatus
	Data   map[string]interface{}
}

type BaseAgent struct {
	ID       string
	AppState *AppState
	TaskChan <-chan ScanTask
}

func (ba *BaseAgent) Run() {}
