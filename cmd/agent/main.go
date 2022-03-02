package main

import (
	"context"
	"fmt"
	"log"
	"net"

	"github.com/nedostupno/zinaida/internal/config"
	"github.com/nedostupno/zinaida/proto/agent"
	"github.com/nedostupno/zinaida/proto/manager"
	"github.com/nedostupno/zinaida/stat"
	"google.golang.org/grpc"
)

func main() {
	cfg, err := config.GetAgentConfig()
	if err != nil {
		log.Fatal(err)
	}

	addr := fmt.Sprintf("%s:%d", cfg.Manager.Ip, cfg.Manager.Port)
	conn, err := grpc.Dial(addr, grpc.WithInsecure())
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	c := manager.NewManagerClient(conn)
	r := &manager.RegistrateRequest{}

	// TODO: Если домен не пустой, то необходимо проверить его существование.
	// В случае, если ресурсные записи не отдаются, то написать об этом в лог
	//
	// Если ресурсные записи отдаются, то получаем A запись и проверяем,
	// что этот ip поднят на одном из интерфейсов.
	domain := cfg.Agent.Domain

	ip := cfg.Agent.Ip

	// TODO: если домен не указан, то необходимо взять тот ip,
	// что настроен на одном из поднятых интерфейсах,
	// а не получать его из конфига
	if domain == "" {
		r.Node = &manager.RegistrateRequest_Ip{ip}
	} else {
		r.Node = &manager.RegistrateRequest_Domain{domain}
	}

	resp, err := Registrate(context.Background(), c, r)
	if err != nil {
		log.Println("Yps...... Nice Error: ", err)
	}

	fmt.Println(resp)

	RunServer(cfg)
}

func Registrate(ctx context.Context, c manager.ManagerClient, r *manager.RegistrateRequest) (*manager.RegistrateResponse, error) {
	return c.Registrate(ctx, r)
}

type server struct {
	agent.UnimplementedAgentServer
}

func RunServer(cfg *config.AgentConfig) {
	srv := grpc.NewServer()
	port := cfg.Agent.Port
	// TODO: Если ip не указан, то нужно взять тот ip, что настроен на одном из поднятых интерфейсах,
	// а не получать его из конфига
	ip := cfg.Agent.Ip

	lis, err := net.Listen("tcp", fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	var s server
	agent.RegisterAgentServer(srv, s)

	if err := srv.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %s", err)
	}
}

func (s server) GetServerStat(ctx context.Context, r *agent.GetServerStatRequest) (*agent.GetServerStatResponse, error) {
	cpu, err := stat.GetCPUPercent()
	if err != nil {
		return nil, err
	}

	la, err := stat.GetLA()
	if err != nil {
		return nil, err
	}

	mem, err := stat.GetMemInfo()
	if err != nil {
		return nil, err
	}

	disk, err := stat.GetDiskInfo("/")
	if err != nil {
		return nil, err
	}

	topProc, err := stat.GetTopProc()
	if err != nil {
		return nil, err
	}

	response := &agent.GetServerStatResponse{
		ServerStat: &agent.ServerStat{
			La: &agent.LA{
				One:     la.One,
				Five:    la.Five,
				Fifteen: la.Fifteen,
			},
			Mem: &agent.Mem{
				Total:     mem.Total,
				Used:      mem.Used,
				Free:      mem.Free,
				Buffers:   mem.Buffers,
				Cache:     mem.Cache,
				SwapTotal: mem.SwapTotal,
				SwapUsed:  mem.SwapUsed,
				SwapFree:  mem.SwapFree,
			},
			Cpu: &agent.CPU{
				CPUPercent: []*agent.CPUPercent{},
			},
			Disk: &agent.Disk{
				Total:      disk.Total,
				Used:       disk.Used,
				InodeTotal: disk.InodesTotal,
				InodesUsed: disk.InodesUsed,
			},
			TopProc: &agent.TopProc{
				Process: []*agent.Process{},
			},
		},
		Err: "",
	}

	for i := 0; i < len(cpu); i++ {
		response.ServerStat.Cpu.CPUPercent = append(response.ServerStat.Cpu.CPUPercent, &agent.CPUPercent{
			CPU:     cpu[i].Cpu,
			Usage:   cpu[i].Usage,
			User:    cpu[i].User,
			System:  cpu[i].System,
			Nice:    cpu[i].Nice,
			Idle:    cpu[i].Idle,
			IOWait:  cpu[i].IOWait,
			IRQ:     cpu[i].IRQ,
			SoftIRQ: cpu[i].SoftIRQ,
		})
	}

	for i := 0; i < len(topProc.Process); i++ {
		response.ServerStat.TopProc.Process = append(response.ServerStat.TopProc.Process, &agent.Process{
			User:    topProc.Process[i].User,
			PID:     topProc.Process[i].PID,
			CPU:     topProc.Process[i].CPU,
			MEM:     topProc.Process[i].MEM,
			VSZ:     topProc.Process[i].VSZ,
			RSS:     topProc.Process[i].RSS,
			TTY:     topProc.Process[i].TTY,
			Stat:    topProc.Process[i].Stat,
			Start:   topProc.Process[i].Start,
			Time:    topProc.Process[i].Time,
			Command: topProc.Process[i].Command,
		})
	}
	return response, nil
}
