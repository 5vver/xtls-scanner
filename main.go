package main

import (
	"log"
	"os"
	"os/signal"
	"sync"

	// "sync"
	"syscall"
)

func main() {
	appState := NewAppState()

	ioAgent := NewIOAgent(appState)
	tcpAgent := NewTCPAgent(appState)
	pingAgent := NewPingAgent(appState)

	var wg sync.WaitGroup
	wg.Add(1)

	const waitInterval int = 2

	go ioAgent.Run()
	go pingAgent.Run(waitInterval)
	go tcpAgent.Run(waitInterval)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Received shutdown signal")
		appState.mu.Lock()
		appState.Stop = true
		appState.mu.Unlock()
		wg.Done()
	}()

	wg.Wait()
}
