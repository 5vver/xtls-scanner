package main

import (
	"fmt"
	"log/slog"
	"net"
	"sync"
)

type Host struct {
	IP     net.IP
	Port   int
	Origin string
}

type ScanTask struct {
	// sni, tls, ping
	Type    string
	Host    Host
	Timeout int
}

type AppState struct {
	mu         sync.RWMutex
	AgentChans map[string]chan ScanTask
	Host       Host
	Timeout    int
	Output     map[string]AgentOutput
	Stop       bool
}

func NewAppState() *AppState {
	return &AppState{
		AgentChans: make(map[string]chan ScanTask, 10),
		Output:     make(map[string]AgentOutput),
	}
}

func (as *AppState) AddChanTask(key string, task ScanTask) error {
	as.mu.Lock()
	defer as.mu.Unlock()

	ch, exists := as.AgentChans[key]
	if !exists {
		ch = make(chan ScanTask, 10)
		as.AgentChans[key] = ch
	}

	select {
	case ch <- task:
		slog.Debug("State channel received task", "key", key)
		return nil
	default:
		return fmt.Errorf("Channel for key %s is full", key)
	}
}

func (as *AppState) GetChanTask(key string) chan ScanTask {
	as.mu.RLock()
	defer as.mu.RUnlock()
	return as.AgentChans[key]
}

func (as *AppState) RemoveChanTask(key string) {
	as.mu.Lock()
	defer as.mu.Unlock()

	if ch, exists := as.AgentChans[key]; exists {
		close(ch)
		delete(as.AgentChans, key)
	}
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

func (as *AppState) SetAgentOutput(agentID string, status AgentStatus, data map[string]any) {
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
