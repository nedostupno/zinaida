package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/nedostupno/zinaida/proto/agent"
	"github.com/nedostupno/zinaida/proto/manager"
	"github.com/nedostupno/zinaida/stat"
	"google.golang.org/grpc"
)

func main() {
	managerIP := os.Getenv("ZINAIDA_IP")

	conn, err := grpc.Dial(managerIP+":22842", grpc.WithInsecure())
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	c := manager.NewManagerClient(conn)
	r := &manager.RegistrateRequest{}
	domain := os.Getenv("DOMAIN_AGENT")
	ip := os.Getenv("IP_AGENT")

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

	RunServer()
}

func Registrate(ctx context.Context, c manager.ManagerClient, r *manager.RegistrateRequest) (*manager.RegistrateResponse, error) {
	return c.Registrate(ctx, r)
}

type server struct {
	agent.UnimplementedAgentServer
}

func RunServer() {
	srv := grpc.NewServer()
	port := 22843
	ip := os.Getenv("IP_AGENT")

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
				CPUPercent: make([]*agent.CPUPercent, 5),
			},
			Disk: &agent.Disk{
				Total:      disk.Total,
				Used:       disk.Used,
				InodeTotal: disk.InodesTotal,
				InodesUsed: disk.InodesUsed,
			},
			TopProc: &agent.TopProc{
				FirstProc:  topProc.First,
				SecondProc: topProc.Second,
				ThirdProc:  topProc.Third,
				FourthProc: topProc.Fourth,
				FifthProc:  topProc.Fifth,
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
	return response, nil
}
