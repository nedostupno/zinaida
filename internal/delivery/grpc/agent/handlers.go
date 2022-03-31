package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"time"

	"github.com/nedostupno/zinaida/proto/protoAgent"
	"github.com/nedostupno/zinaida/proto/protoManager"
	"github.com/nedostupno/zinaida/stat"
	"google.golang.org/grpc"
)

func (s *server) Registrate() error {
	addr := fmt.Sprintf("%s:%d", s.cfg.Manager.Ip, s.cfg.Manager.Port)
	conn, err := grpc.Dial(addr, grpc.WithInsecure())
	if err != nil {
		return err
	}
	defer conn.Close()

	c := protoManager.NewManagerClient(conn)
	r := &protoManager.RegistrateRequest{}

	domain := s.cfg.Agent.Domain

	ip := s.cfg.Agent.Ip

	// Получаем адреса на поднятых интерфейсах
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return err
	}

	// Получаем слайс ip адрессов, поднятных на интерфейсах, кроме loopback
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
		return errors.New("no ipv4 addresses found on interfaces other than loopback")
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
				return fmt.Errorf("non-existent domain passed in config. Domain: %s", domain)
			}
			return fmt.Errorf("failed to find ip for domain %s : %+v", domain, err)
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
			return fmt.Errorf("domain %s specified in the config is not directed to the agent node server", domain)
		}

		r.Domain = domain
		r.Ip = ips[ipIndex]
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(s.cfg.Agent.RegistrateTimeout)*time.Millisecond)
	defer cancel()

	_, err = c.Registrate(ctx, r)
	if err != nil {
		return fmt.Errorf("failed to register node: %v. Error: %v", r, err)
	}

	return nil
}

func (s *server) Ping(ctx context.Context, r *protoAgent.PingRequest) (*protoAgent.PingResponse, error) {
	return &protoAgent.PingResponse{}, nil
}

func (s *server) Reboot(ctx context.Context, r *protoAgent.RebootRequest) (*protoAgent.RebootResponse, error) {

	cmd := exec.Command("shutdown", "-r")
	err := cmd.Run()
	if err != nil {
		return nil, err
	}

	return &protoAgent.RebootResponse{}, nil
}

func (s *server) GetServerStat(ctx context.Context, r *protoAgent.GetServerStatRequest) (*protoAgent.GetServerStatResponse, error) {
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

	response := &protoAgent.GetServerStatResponse{
		ServerStat: &protoAgent.ServerStat{
			La: &protoAgent.LA{
				One:     la.One,
				Five:    la.Five,
				Fifteen: la.Fifteen,
			},
			Mem: &protoAgent.Mem{
				Total:     mem.Total,
				Used:      mem.Used,
				Free:      mem.Free,
				Buffers:   mem.Buffers,
				Cache:     mem.Cache,
				SwapTotal: mem.SwapTotal,
				SwapUsed:  mem.SwapUsed,
				SwapFree:  mem.SwapFree,
			},
			Cpu: &protoAgent.CPU{
				CPUPercent: []*protoAgent.CPUPercent{},
			},
			Disk: &protoAgent.Disk{
				Total:      disk.Total,
				Used:       disk.Used,
				InodeTotal: disk.InodesTotal,
				InodesUsed: disk.InodesUsed,
			},
			TopProc: &protoAgent.TopProc{
				Process: []*protoAgent.Process{},
			},
		},
		Err: "",
	}

	for i := 0; i < len(cpu); i++ {
		response.ServerStat.Cpu.CPUPercent = append(response.ServerStat.Cpu.CPUPercent, &protoAgent.CPUPercent{
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
		response.ServerStat.TopProc.Process = append(response.ServerStat.TopProc.Process, &protoAgent.Process{
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
