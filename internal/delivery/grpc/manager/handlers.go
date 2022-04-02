package manager

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/nedostupno/zinaida/proto/protoAgent"
	"github.com/nedostupno/zinaida/proto/protoManager"
	"google.golang.org/grpc"
)

func (s *Server) Registrate(ctx context.Context, r *protoManager.RegistrateRequest) (*protoManager.RegistrateResponse, error) {
	domain := r.GetDomain()
	ip := r.GetIp()

	if domain != "" {
		// Проверяем существование домена и получаем его ip адрес
		ips, err := net.LookupHost(domain)
		if err != nil {
			if r, ok := err.(*net.DNSError); ok && r.IsNotFound {
				return nil, fmt.Errorf("transferred domain does not exist ")
			}
			return nil, fmt.Errorf("failed to find ip for domain %s : %+v", domain, err)
		}
		// Проверяем является ли переданный нам ip адрес одним из тех,
		// что указаны в ресурсных записях домена
		var ok bool
		for _, i := range ips {
			if i == ip {
				ok = true
			}
		}

		if !ok {
			return nil, fmt.Errorf("the passed ip address and the ip address from the A record of the domain do not match")
		}
	}

	isExist, err := s.repo.CheckNodeExistenceByIP(ip)
	if err != nil {
		return nil, err
	}

	if isExist {
		return nil, fmt.Errorf("this node is already exist in monitoring")
	}

	_, err = s.repo.AddNode(ip, domain)
	if err != nil {
		return nil, err
	}

	node, err := s.repo.GetNodeByIP(ip)
	if err != nil {
		return nil, err
	}

	resp := &protoManager.RegistrateResponse{
		NodeAgent: &protoManager.NodeAgent{
			Id:     int64(node.Id),
			Ip:     node.Ip,
			Domain: node.Domain,
		},
	}
	return resp, nil
}

func (s *Server) GetStat(ip string, port int) (*protoAgent.GetServerStatResponse, error) {

	conn, err := grpc.Dial(fmt.Sprintf("%v:%d", ip, port), grpc.WithInsecure())
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	c := protoAgent.NewAgentClient(conn)
	r := &protoAgent.GetServerStatRequest{}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(s.cfg.Grpc.GetStatTimeout)*time.Millisecond)
	defer cancel()
	resp, err := c.GetServerStat(ctx, r)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (s *Server) Ping(ip string, port int, timeout int) (*protoAgent.PingResponse, error) {
	conn, err := grpc.Dial(fmt.Sprintf("%v:%d", ip, port), grpc.WithInsecure())
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	c := protoAgent.NewAgentClient(conn)
	r := &protoAgent.PingRequest{}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Millisecond)
	defer cancel()

	resp, err := c.Ping(ctx, r)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (s *Server) RebootNode(ip string, port int) (*protoAgent.RebootResponse, error) {
	conn, err := grpc.Dial(fmt.Sprintf("%v:%d", ip, port), grpc.WithInsecure())
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	c := protoAgent.NewAgentClient(conn)
	r := &protoAgent.RebootRequest{}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(s.cfg.Grpc.RebootTimeout)*time.Millisecond)
	defer cancel()
	resp, err := c.Reboot(ctx, r)
	if err != nil {
		return nil, err
	}
	return resp, nil
}
