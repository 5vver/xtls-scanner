package main

func main() {
	appState := NewAppState()
	taskChan := make(chan ScanTask, 10)

	ioAgent := NewIOAgent(appState)
	sniAgent := NewSNIAgent(appState, taskChan)

	go ioAgent.Run()
	go sniAgent.Run()

	select {}
}
