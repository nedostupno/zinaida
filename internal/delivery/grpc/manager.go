package grpc

import (
	"context"
	"fmt"
	"net"
	"os"

	"github.com/nedostupno/zinaida/internal/repository"
	"github.com/nedostupno/zinaida/logger"
	"github.com/nedostupno/zinaida/proto/agent"
	"github.com/nedostupno/zinaida/proto/manager"
	"google.golang.org/grpc"
)

type server struct {
	repo   *repository.Repository
	logger *logger.Logger
	manager.UnimplementedManagerServer
}

func (s server) Registrate(ctx context.Context, r *manager.RegistrateRequest) (*manager.RegistrateResponse, error) {
	domain := r.GetDomain()
	ip := r.GetIp()

	if ip == "" {
		ip, err := net.ResolveIPAddr("ip4", domain)
		if err != nil {
			return nil, err
		}

		isExist, err := s.repo.CheckNodeExistenceByIP(ip.String())
		if err != nil {
			return nil, err
		}

		if isExist {
			return nil, fmt.Errorf("данная нода уже добавлена в мониторинг")
		}

		_, err = s.repo.AddNode(ip.String(), domain)
		if err != nil {
			return nil, err
		}

		node, err := s.repo.GetNodeByIP(ip.String())
		if err != nil {
			return nil, err
		}

		resp := &manager.RegistrateResponse{
			NodeAgent: &manager.NodeAgent{
				Id:     int64(node.Id),
				Ip:     node.Ip,
				Domain: node.Domain,
			},
		}
		return resp, nil
	}

	isExist, err := s.repo.CheckNodeExistenceByIP(ip)
	if err != nil {
		return nil, err
	}

	if isExist {
		return nil, fmt.Errorf("данная нода уже добавлена в мониторинг")
	}

	_, err = s.repo.AddNode(ip, "")
	if err != nil {
		return nil, err
	}

	node, err := s.repo.GetNodeByIP(ip)
	if err != nil {
		return nil, err
	}

	resp := &manager.RegistrateResponse{
		NodeAgent: &manager.NodeAgent{
			Id:     int64(node.Id),
			Ip:     node.Ip,
			Domain: node.Domain,
		},
	}
	return resp, nil
}

func RunServer(repo *repository.Repository, log *logger.Logger) {
	srv := grpc.NewServer()
	port := 22842
	ip := os.Getenv("ZINAIDA_IP")

	lis, err := net.Listen("tcp", fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	var s server
	s.logger = log
	s.repo = repo
	manager.RegisterManagerServer(srv, s)

	if err := srv.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %s", err)
	}
}

func GetStat(ip string) (*agent.GetServerStatResponse, error) {

	conn, err := grpc.Dial(fmt.Sprintf("%v:22843", ip), grpc.WithInsecure())
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	c := agent.NewAgentClient(conn)
	r := &agent.GetServerStatRequest{}

	resp, err := c.GetServerStat(context.Background(), r)
	if err != nil {
		return nil, err
	}
	return resp, nil

	// c := manager.NewManagerClient(conn)
	// r := &manager.RegistrateRequest{}
	// domain := os.Getenv("DOMAIN_AGENT")
	// ip := os.Getenv("IP_AGENT")

	// if domain == "" {
	// 	r.Node = &manager.RegistrateRequest_Ip{ip}
	// } else {
	// 	r.Node = &manager.RegistrateRequest_Domain{domain}
	// }

	// resp, err := Registrate(context.Background(), c, r)
	// if err != nil {
	// 	log.Println("Yps...... Nice Error: ", err)
	// }

	// fmt.Println(resp)
}
