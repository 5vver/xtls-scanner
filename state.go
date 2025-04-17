package main

import (
	"net"
	"sync"
)

type Host struct {
	IP     net.IP
	Port   int
	Origin string
}

type AppState struct {
	mu      sync.RWMutex
	Tasks   map[string]bool
	Host    Host
	Timeout int
	Output  map[string]AgentOutput
	Stop    bool
}

func NewAppState() *AppState {
	return &AppState{
		Tasks:  make(map[string]bool),
		Output: make(map[string]AgentOutput),
	}
}

func (as *AppState) SetTask(task string, enabled bool) {
	as.mu.Lock()
	defer as.mu.Unlock()
	as.Tasks[task] = enabled
}

func (as *AppState) SetHost(host Host) {
	as.mu.Lock()
	defer as.mu.Unlock()
	as.Host = host
}

func (as *AppState) SetTimeout(timeout int) {
	as.mu.Lock()
	defer as.mu.Unlock()
	as.Timeout = timeout
}

func (as *AppState) SetAgentOutput(agentID string, status AgentStatus, data map[string]interface{}) {
	as.mu.Lock()
	defer as.mu.Unlock()
	as.Output[agentID] = AgentOutput{Status: status, Data: data}
}

func (as *AppState) GetAgentOutput(agentID string) (AgentOutput, bool) {
	as.mu.RLock()
	defer as.mu.RUnlock()
	output, exists := as.Output[agentID]
	return output, exists
}

func (as *AppState) ShouldExecute(task string) bool {
	as.mu.RLock()
	defer as.mu.RUnlock()
	return as.Tasks[task] && !as.Stop
}
