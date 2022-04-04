package manager

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/nedostupno/zinaida/internal/auth"
	"github.com/nedostupno/zinaida/proto/protoAgent"
	"github.com/nedostupno/zinaida/proto/protoManager"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
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

func (s *Server) Ping(ip string, port int) (*protoAgent.PingResponse, error) {
	conn, err := grpc.Dial(fmt.Sprintf("%v:%d", ip, port), grpc.WithInsecure())
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	c := protoAgent.NewAgentClient(conn)
	r := &protoAgent.PingRequest{}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(s.cfg.Grpc.PingTimeout)*time.Millisecond)
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

func (s *Server) GetNode(ctx context.Context, r *protoManager.GetNodeRequest) (*protoManager.GetNodeResponse, error) {
	internalError := &protoManager.GetNodeResponse{
		Result: &protoManager.GetNodeResponse_Error_{
			Error: &protoManager.GetNodeResponse_Error{
				Message: "An unexpected error has occurred",
				Code:    0,
			},
		},
	}

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		s.logger.WhithErrorFields(fmt.Errorf("failed to get metadata from incomming context")).Error()
		md.Append("x-http-code", "500")
		grpc.SendHeader(ctx, md)

		return internalError, nil
	}

	id := int(r.GetId())

	isExist, err := s.repo.Nodes.CheckNodeExistenceByID(id)
	if err != nil {
		s.logger.WhithErrorFields(err).Errorf("failed check node existence by id %d in database", id)
		md.Append("x-http-code", "500")
		grpc.SendHeader(ctx, md)

		return internalError, nil
	}

	if !isExist {
		md.Append("x-http-code", "404")
		grpc.SendHeader(ctx, md)

		resp := &protoManager.GetNodeResponse{
			Result: &protoManager.GetNodeResponse_Error_{
				Error: &protoManager.GetNodeResponse_Error{
					Message: fmt.Sprintf("node with id %d does not exist", id),
					Code:    1,
				},
			},
		}

		return resp, nil
	}

	node, err := s.repo.GetNodeByID(id)
	if err != nil {
		md.Append("x-http-code", "500")
		grpc.SendHeader(ctx, md)

		return internalError, nil
	}

	resp := &protoManager.GetNodeResponse{
		Result: &protoManager.GetNodeResponse_NodeAgent{
			NodeAgent: &protoManager.NodeAgent{
				Id:     int64(node.Id),
				Ip:     node.Ip,
				Domain: node.Domain,
			},
		},
	}

	md.Append("x-http-code", "200")
	grpc.SendHeader(ctx, md)

	return resp, nil
}

func (s *Server) Login(ctx context.Context, r *protoManager.LoginRequest) (*protoManager.LoginResponse, error) {
	internalError := &protoManager.LoginResponse{
		Result: &protoManager.LoginResponse_Error_{
			Error: &protoManager.LoginResponse_Error{
				Message: "An unexpected error has occurred",
				Code:    0,
			},
		},
	}

	IncorrectDataError := &protoManager.LoginResponse{
		Result: &protoManager.LoginResponse_Error_{
			Error: &protoManager.LoginResponse_Error{
				Message: "Incorrect data sent",
				Code:    1,
			},
		},
	}

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		s.logger.WhithErrorFields(fmt.Errorf("failed to get metadata from incomming context")).Error()
		md.Append("x-http-code", "500")
		grpc.SendHeader(ctx, md)
		return internalError, nil
	}

	exist, err := s.repo.Users.IsExist(r.Username)
	if err != nil {
		s.logger.WhithErrorFields(err).Errorf("failed to check the existence of user %s in the database", r.Username)
		md.Append("x-http-code", "500")
		grpc.SendHeader(ctx, md)
		return internalError, nil
	}

	if !exist {
		md.Append("x-http-code", "401")
		grpc.SendHeader(ctx, md)
		return IncorrectDataError, nil
	}

	user, err := s.repo.Users.Get(r.Username)
	if err != nil {
		s.logger.WhithErrorFields(err).Errorf("failed to get user %s from database", r.Username)
		md.Append("x-http-code", "500")
		grpc.SendHeader(ctx, md)
		return internalError, nil
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(r.Password))

	if r.Username == user.Username && err == nil {
		jwt, err := auth.GenerateJWTToken(user.Username, s.cfg.Jwt.SecretKeyForAccessToken, s.cfg.Jwt.AccessTokenTTL)
		if err != nil {
			s.logger.WhithErrorFields(err).Errorf("failed to generate JWT access token for user %s", user.Username)
			md.Append("x-http-code", "500")
			grpc.SendHeader(ctx, md)
			return internalError, nil
		}

		refresh, err := auth.GenerateRefreshToken(user.Username, s.cfg.Jwt.SecretKeyForRefreshToken, s.cfg.Jwt.RefreshTokenTTL)
		if err != nil {
			s.logger.WhithErrorFields(err).Errorf("failed to generate JWT refresh token for user %s ", user.Username)
			md.Append("x-http-code", "500")
			grpc.SendHeader(ctx, md)
			return internalError, nil
		}

		_, err = s.repo.Users.UpdateRefreshToken(user.Username, refresh)
		if err != nil {
			s.logger.WhithErrorFields(err).Errorf("failed to update JWT refresh token in database for user %s ", user.Username)
			md.Append("x-http-code", "500")
			grpc.SendHeader(ctx, md)
			return internalError, nil
		}

		md.Append("x-http-code", "200")
		grpc.SendHeader(ctx, md)

		resp := &protoManager.LoginResponse{
			Result: &protoManager.LoginResponse_Jwt{
				Jwt: &protoManager.JWT{
					AccessToken:  jwt,
					RefreshToken: refresh,
				},
			},
		}
		return resp, nil
	}

	md.Append("x-http-code", "401")
	grpc.SendHeader(ctx, md)
	return IncorrectDataError, nil
}
