package main

import (
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

func main() {
	appState := NewAppState()
	taskChan := make(chan ScanTask, 10)

	ioAgent := NewIOAgent(appState, taskChan)
	sniAgent := NewSNIAgent(appState, taskChan)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		ioAgent.Run()
		wg.Done()
	}()
	go func() {
		sniAgent.Run()
		wg.Done()
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Received shutdown signal")
		appState.mu.Lock()
		appState.Stop = true
		appState.mu.Unlock()
		close(taskChan)
	}()

	wg.Wait()
}
