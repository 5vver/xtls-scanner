package main

import (
	"fmt"
	"log"
	"time"

	probing "github.com/prometheus-community/pro-bing"
)

type PingAgent struct {
	BaseAgent
}

func NewPingAgent(appState *AppState) *PingAgent {
	return &PingAgent{
		BaseAgent: BaseAgent{
			ID:       "ping",
			AppState: appState,
		},
	}
}

func (pa *PingAgent) Run(interval int) {
	log.Printf("Starting %s Scanner Agent (%s) and listening for tasks..", "ping", pa.ID)

	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	for {
		if pa.AppState.Stop {
			log.Println("[PING] stopping")
			break
		}

		taskChan := pa.AppState.GetChanTask(pa.ID)
		if taskChan == nil {
			log.Println("Ping channel not initialized yet, waiting...")
			<-ticker.C
			continue
		}

		select {
		case task, ok := <-taskChan:
			if !ok {
				log.Println("Task channel closed, stopping agent")
				return
			}

			log.Println("Received task:", task)

			pa.AppState.SetAgentOutput(pa.ID, AgentStatusRunning, nil)

			// hostPort := net.JoinHostPort(task.Host.IP.String(), strconv.Itoa(task.Host.Port))
			pinger, err := probing.NewPinger(task.Host.Origin)
			if err != nil {
				log.Println(fmt.Errorf("Error creating pinger: %w", err))
				pa.AppState.SetAgentOutput(pa.ID, AgentStatusFailed, nil)
				return
			}

			pinger.OnRecv = func(pkt *probing.Packet) {
				fmt.Printf("%d bytes from %s: icmp_seq=%d time=%v ttl=%v\n",
					pkt.Nbytes, pkt.IPAddr, pkt.Seq, pkt.Rtt, pkt.TTL)
			}
			pinger.OnDuplicateRecv = func(pkt *probing.Packet) {
				fmt.Printf("%d bytes from %s: icmp_seq=%d time=%v ttl=%v (DUP!)\n",
					pkt.Nbytes, pkt.IPAddr, pkt.Seq, pkt.Rtt, pkt.TTL)
			}
			pinger.OnFinish = func(stats *probing.Statistics) {
				pa.AppState.SetAgentOutput(pa.ID, AgentStatusCompleted, nil)
				fmt.Printf("\n--- %s ping statistics ---\n", stats.Addr)
				fmt.Printf("%d packets transmitted, %d packets received, %d duplicates, %v%% packet loss\n",
					stats.PacketsSent, stats.PacketsRecv, stats.PacketsRecvDuplicates, stats.PacketLoss)
				fmt.Printf("round-trip min/avg/max/stddev = %v/%v/%v/%v\n",
					stats.MinRtt, stats.AvgRtt, stats.MaxRtt, stats.StdDevRtt)
			}

			pinger.Count = -1
			pinger.Size = 24
			pinger.Interval = time.Second
			pinger.Timeout = time.Duration(task.Timeout) * time.Second
			pinger.TTL = 64
			pinger.InterfaceName = ""
			pinger.SetPrivileged(false)
			pinger.SetTrafficClass(uint8(192))

			fmt.Printf("PING %s (%s):\n", pinger.Addr(), pinger.IPAddr())
			err = pinger.Run()
			if err != nil {
				pa.AppState.SetAgentOutput(pa.ID, AgentStatusFailed, nil)
				fmt.Println("Failed to ping target host:", err)
				return
			}

		case <-ticker.C:
			log.Println("[PING] No tasks available, waiting...")
		}
	}
}
