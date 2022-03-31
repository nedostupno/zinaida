package manager

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/nedostupno/zinaida/proto/agent"
	"github.com/nedostupno/zinaida/proto/manager"
	"google.golang.org/grpc"
)

func (s *Server) Registrate(ctx context.Context, r *manager.RegistrateRequest) (*manager.RegistrateResponse, error) {
	domain := r.GetDomain()
	ip := r.GetIp()

	if domain != "" {
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
	}

	_, err := s.repo.AddNode(ip, domain)
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

func (s *Server) GetStat(ip string, port int) (*agent.GetServerStatResponse, error) {

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
}

func (s *Server) Ping(ip string, port int, timeout int) (*agent.PingResponse, error) {
	conn, err := grpc.Dial(fmt.Sprintf("%v:%d", ip, port), grpc.WithInsecure())
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	c := agent.NewAgentClient(conn)
	r := &agent.PingRequest{}
	cntx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	resp, err := c.Ping(cntx, r)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (s *Server) RebootNode(ip string, port int) (*agent.RebootResponse, error) {
	conn, err := grpc.Dial(fmt.Sprintf("%v:%d", ip, port), grpc.WithInsecure())
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	c := agent.NewAgentClient(conn)
	r := &agent.RebootRequest{}

	resp, err := c.Reboot(context.Background(), r)
	if err != nil {
		return nil, err
	}
	return resp, nil
}
