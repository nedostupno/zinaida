package grpc

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/nedostupno/zinaida/internal/config"
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

	ips, err := net.LookupHost(domain)
	if err != nil {
		if r, ok := err.(*net.DNSError); ok && r.IsNotFound {
			return nil, fmt.Errorf("передан не существующий домен")
		}
		return nil, fmt.Errorf("не удалось узнать ip домена")
	}
	var ok bool
	for _, i := range ips {
		if i == ip {
			ok = true
		}
	}

	if !ok {
		return nil, fmt.Errorf("переданный ip адрес и ip адерс из А записи домена не совпадают")
	}

	isExist, err := s.repo.CheckNodeExistenceByIP(ip)
	if err != nil {
		return nil, err
	}

	if isExist {
		return nil, fmt.Errorf("данная нода уже добавлена в мониторинг")
	}

	_, err = s.repo.AddNode(ip, domain)
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

func RunServer(repo *repository.Repository, log *logger.Logger, cfg *config.ManagerConfig) {
	srv := grpc.NewServer()
	port := cfg.Grpc.Port
	ip := cfg.Grpc.Ip

	lis, err := net.Listen("tcp", fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		log.WhithErrorFields(err).Fatalf("Не удалось начать прослушивать адрес %s:%d", ip, port)
	}

	var s server
	s.logger = log
	s.repo = repo
	manager.RegisterManagerServer(srv, s)

	if err := srv.Serve(lis); err != nil {
		log.WhithErrorFields(err).Fatalf("Не удалось начать обслуживать grpc сервер")
	}
}

func GetStat(ip string, port int) (*agent.GetServerStatResponse, error) {

	conn, err := grpc.Dial(fmt.Sprintf("%v:%d", ip, port), grpc.WithInsecure())
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

func Ping(ip string, port int) (*agent.PingResponse, error) {
	conn, err := grpc.Dial(fmt.Sprintf("%v:%d", ip, port), grpc.WithInsecure())
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	c := agent.NewAgentClient(conn)
	r := &agent.PingRequest{}
	cntx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	resp, err := c.Ping(cntx, r)
	if err != nil {
		return nil, err
	}
	return resp, nil
}
