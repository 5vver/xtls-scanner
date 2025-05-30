package main

import (
	"log/slog"
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
	slog.Info("Starting Ping scanner agent and listening for tasks")

	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	for {
		if pa.AppState.Stop {
			slog.Debug("Stopping Ping agent")
			break
		}

		taskChan := pa.AppState.GetChanTask(pa.ID)
		if taskChan == nil {
			slog.Debug("Ping channel not initialized yet, waiting")
			<-ticker.C
			continue
		}

		select {
		case task, ok := <-taskChan:
			if !ok {
				slog.Debug("Task channel closed, stopping Ping agent")
				return
			}

			slog.Debug("Ping agent received task", "task", task)
			slog.Info("Ping agent starts processing task, please stand by")

			pa.AppState.SetAgentOutput(pa.ID, AgentStatusRunning, nil)

			// hostPort := net.JoinHostPort(task.Host.IP.String(), strconv.Itoa(task.Host.Port))
			pinger, err := probing.NewPinger(task.Host.Origin)
			if err != nil {
				slog.Error("Error creating pinger", "error", err)
				pa.AppState.SetAgentOutput(pa.ID, AgentStatusFailed, nil)
				return
			}

			pinger.OnRecv = func(pkt *probing.Packet) {
				slog.Debug("Ping agent received bytes", "from", pkt.IPAddr, "amount", pkt.Nbytes, "icmp_seq",
					pkt.Seq, "time", pkt.Rtt, "ttl", pkt.TTL)
			}
			pinger.OnDuplicateRecv = func(pkt *probing.Packet) {
				slog.Debug("Ping agent duplicate received bytes", "from", pkt.IPAddr, "amount", pkt.Nbytes, "icmp_seq",
					pkt.Seq, "time", pkt.Rtt, "ttl", pkt.TTL)
			}
			pinger.OnFinish = func(stats *probing.Statistics) {
				slog.Info("Ping agent finished work. Press Ctrl + C to stop agents")
				result := map[string]any{
					"address":    stats.Addr,
					"sent":       stats.PacketsSent,
					"received":   stats.PacketsRecv,
					"duplicates": stats.PacketsRecvDuplicates,
					"loss":       stats.PacketLoss,
					"minRtt":     stats.MinRtt,
					"maxRtt":     stats.MaxRtt,
					"avgRtt":     stats.AvgRtt,
					"stdDevRtt":  stats.StdDevRtt,
				}
				pa.AppState.SetAgentOutput(pa.ID, AgentStatusCompleted, result)
			}

			pinger.Count = -1
			pinger.Size = 24
			pinger.Interval = time.Second
			pinger.Timeout = time.Duration(task.Timeout) * time.Second
			pinger.TTL = 64
			pinger.InterfaceName = ""
			pinger.SetPrivileged(false)
			pinger.SetTrafficClass(uint8(192))

			slog.Debug("Pinging", "addr", pinger.Addr(), "ip", pinger.IPAddr())
			err = pinger.Run()
			if err != nil {
				pa.AppState.SetAgentOutput(pa.ID, AgentStatusFailed, nil)
				slog.Error("Failed to ping target host", "error", err)
				return
			}

		case <-ticker.C:
			slog.Debug("Ping agent no tasks available, waiting")
		}
	}
}
