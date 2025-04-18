package main

import (
	"fmt"
	"log"
	"net"
	"sync"
)

type Host struct {
	IP     net.IP
	Port   int
	Origin string
}

type ScanTask struct {
	// sni, tcp, ping
	Type    string
	Host    Host
	Timeout int
}

type AppState struct {
	mu         sync.RWMutex
	Tasks      map[string]bool
	AgentChans map[string]chan ScanTask
	Host       Host
	Timeout    int
	Output     map[string]AgentOutput
	Stop       bool
}

func NewAppState() *AppState {
	return &AppState{
		Tasks:      make(map[string]bool),
		AgentChans: make(map[string]chan ScanTask, 10),
		Output:     make(map[string]AgentOutput),
	}
}

func (as *AppState) SetTask(task string, enabled bool) {
	as.mu.Lock()
	defer as.mu.Unlock()
	as.Tasks[task] = enabled
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
		log.Println("Added task for ", key)
		return nil
	default:
		return fmt.Errorf("channel for key %s is full", key)
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
