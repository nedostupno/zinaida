package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os/exec"

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

	RunServer(cfg)
}

func Registrate(cfg *config.AgentConfig) error {
	addr := fmt.Sprintf("%s:%d", cfg.Manager.Ip, cfg.Manager.Port)
	conn, err := grpc.Dial(addr, grpc.WithInsecure())
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	c := manager.NewManagerClient(conn)
	r := &manager.RegistrateRequest{}

	domain := cfg.Agent.Domain

	ip := cfg.Agent.Ip

	// Получаем адреса на поднятых интерфейсах
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Fatal(err)
	}

	// Получаем слайс ip адрессов, поднятных на интерфейсх, кроме loopback
	var ipOnInerfaces []string
	for _, a := range addrs {
		if IPNet, ok := a.(*net.IPNet); ok && !IPNet.IP.IsLoopback() {
			// Если у нас адрес IPv6, то метод To4 вернет nil
			if IPNet.IP.To16() != nil {
				ipOnInerfaces = append(ipOnInerfaces, IPNet.IP.String())
			}
		}
	}

	if len(ipOnInerfaces) == 0 {
		err = errors.New("не обнаружено ни одного ipv4 адреса на интерфейсах кроме loopback")
		log.Fatal(err)
	}

	// Проверяем является ли переданный ip одним из ip поднятых на интерфейсах
	var ok bool
	for _, i := range ipOnInerfaces {
		if i == ip {
			r.Ip = ip
			ok = true
		}
	}
	if !ok {
		r.Ip = ipOnInerfaces[0]
	}

	// Если не предеан ни домен, ни ip, то регестируем ноду с ip, который поднят на интерфейсе
	if domain == "" && ip == "" {
		r.Ip = ipOnInerfaces[0]
	}

	if domain != "" {
		// Проверяем существование домена и получаем его ip адрес
		ips, err := net.LookupHost(domain)
		if err != nil {
			if r, ok := err.(*net.DNSError); ok && r.IsNotFound {
				log.Fatalln("Передан не существующий домен")
			}
			log.Fatal("Не удалось узнать ip домена")
			return err
		}

		var ipDomainIsCorrect bool
		var ipIndex int

		// Если ip не был передан, то проверяем равен ли ip домена ip на интерфейсе
		for c, i := range ips {
			for _, j := range ipOnInerfaces {
				if i == j {
					ipDomainIsCorrect = true
					ipIndex = c
				}
			}
		}

		if !ipDomainIsCorrect {
			log.Fatal("Домен смотрит не туда")
		}

		r.Domain = domain
		r.Ip = ips[ipIndex]
	}

	resp, err := c.Registrate(context.Background(), r)
	if err != nil {
		log.Printf("не удалось зарегистрировать ноду c данными: %v. Ошибка: %v", r, err)
	}

	fmt.Println(resp)
	return nil
}

type server struct {
	agent.UnimplementedAgentServer
}

func RunServer(cfg *config.AgentConfig) {
	srv := grpc.NewServer()
	port := cfg.Agent.Port
	ip := cfg.Agent.Ip

	lis, err := net.Listen("tcp", fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	var s server
	agent.RegisterAgentServer(srv, s)

	Registrate(cfg)

	if err := srv.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %s", err)
	}
}

func (s server) Ping(ctx context.Context, r *agent.PingRequest) (*agent.PingResponse, error) {
	return &agent.PingResponse{}, nil
}

func (s server) Reboot(ctx context.Context, r *agent.RebootRequest) (*agent.RebootResponse, error) {

	cmd := exec.Command("shutdown", "-r")
	err := cmd.Run()
	if err != nil {
		return nil, err
	}

	return &agent.RebootResponse{}, nil
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
