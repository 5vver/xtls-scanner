package main

type AgentStatus string

const (
	AgentStatusPending   AgentStatus = "pending"
	AgentStatusRunning   AgentStatus = "running"
	AgentStatusCompleted AgentStatus = "completed"
	AgentStatusFailed    AgentStatus = "failed"
)

type AgentOutput struct {
	ID     string
	Status AgentStatus
	Data   map[string]any
}

type BaseAgent struct {
	ID       string
	AppState *AppState
}

func (ba *BaseAgent) Run() {}
