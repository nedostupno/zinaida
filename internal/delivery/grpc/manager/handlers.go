package manager

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"time"
	"unicode/utf8"

	"github.com/golang-jwt/jwt"
	"github.com/nedostupno/zinaida/internal/auth"
	"github.com/nedostupno/zinaida/internal/models"
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

func (s *Server) Reboot(ip string, port int) (*protoAgent.RebootResponse, error) {
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

func (s *Server) Refresh(ctx context.Context, r *protoManager.RefreshRequest) (*protoManager.RefreshResponse, error) {
	invalidRefreshTokenError := &protoManager.RefreshResponse{
		Result: &protoManager.RefreshResponse_Error_{
			Error: &protoManager.RefreshResponse_Error{
				Message: "invalid refresh token",
				Code:    1,
			},
		},
	}

	internalError := &protoManager.RefreshResponse{
		Result: &protoManager.RefreshResponse_Error_{
			Error: &protoManager.RefreshResponse_Error{
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

	if r.RefreshToken == "" {
		md.Append("x-http-code", "400")
		grpc.SendHeader(ctx, md)
		resp := &protoManager.RefreshResponse{
			Result: &protoManager.RefreshResponse_Error_{
				Error: &protoManager.RefreshResponse_Error{
					Message: "Missed refresh token",
					Code:    2,
				},
			},
		}
		return resp, nil
	}

	claims := &auth.CustomClaims{}

	token, err := jwt.ParseWithClaims(r.RefreshToken, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.cfg.Jwt.SecretKeyForRefreshToken), nil
	})

	// Ошибка будет выброшена даже в том случае, если токен истек, так что ручные проверки не требуются
	if err != nil || !token.Valid {
		md.Append("x-http-code", "400")
		grpc.SendHeader(ctx, md)
		return invalidRefreshTokenError, nil
	}

	exist, err := s.repo.Users.IsExist(claims.Username)
	if err != nil {
		s.logger.WhithErrorFields(err).Errorf("failed to check the existence of user %s in the database", claims.Username)
		md.Append("x-http-code", "500")
		grpc.SendHeader(ctx, md)
		return internalError, nil
	}

	if !exist {
		md.Append("x-http-code", "400")
		grpc.SendHeader(ctx, md)
		return invalidRefreshTokenError, nil
	}

	oldRefreshToken, err := s.repo.Users.GetRefreshToken(claims.Username)
	if err != nil {
		s.logger.WhithErrorFields(err).Errorf("failed to get refresh token for user %s from database", claims.Username)
		md.Append("x-http-code", "500")
		grpc.SendHeader(ctx, md)
		return internalError, nil
	}

	if r.RefreshToken != oldRefreshToken {
		md.Append("x-http-code", "400")
		grpc.SendHeader(ctx, md)
		return invalidRefreshTokenError, nil
	}

	newJwt, err := auth.GenerateJWTToken(claims.Username, s.cfg.Jwt.SecretKeyForAccessToken, s.cfg.Jwt.AccessTokenTTL)
	if err != nil {
		s.logger.WhithErrorFields(err).Errorf("failed to generate JWT access token for user %s ", claims.Username)
		md.Append("x-http-code", "500")
		grpc.SendHeader(ctx, md)
		return internalError, nil
	}

	newRefresh, err := auth.GenerateRefreshToken(claims.Username, s.cfg.Jwt.SecretKeyForRefreshToken, s.cfg.Jwt.RefreshTokenTTL)
	if err != nil {
		s.logger.WhithErrorFields(err).Errorf("failed to generate JWT refresh token for user %s", claims.Username)
		md.Append("x-http-code", "500")
		grpc.SendHeader(ctx, md)
		return internalError, nil
	}

	_, err = s.repo.Users.UpdateRefreshToken(claims.Username, newRefresh)
	if err != nil {
		s.logger.WhithErrorFields(err).Errorf("failed to update JWT refresh in token database for user %s", claims.Username)
		md.Append("x-http-code", "500")
		grpc.SendHeader(ctx, md)
		return internalError, nil
	}

	md.Append("x-http-code", "200")
	grpc.SendHeader(ctx, md)
	resp := &protoManager.RefreshResponse{
		Result: &protoManager.RefreshResponse_Jwt{
			Jwt: &protoManager.JWT{
				AccessToken:  newJwt,
				RefreshToken: newRefresh,
			},
		},
	}
	return resp, nil
}

func (s *Server) CreateNode(ctx context.Context, r *protoManager.CreateNodeRequest) (*protoManager.CreateNodeResponse, error) {
	internalError := &protoManager.CreateNodeResponse{
		Result: &protoManager.CreateNodeResponse_Error_{
			Error: &protoManager.CreateNodeResponse_Error{
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

	/*
		Как происходит регистрация ноды в зависимости от переданных данных.


			Нам могут передать:
				- Домен
				- IP
				- Домен + IP


			# Передан только домен:
				- Получаем ip из A записей домена
					- Если не удалось получить ip, то возвращаем ошибку,
					- Если ip получен, то выполняем grpc Ping, чтобы удостовериться, что на сервере установлено и запущенно наше ПО
						- Если Ping прошел успешно, то регистрируем ноду-агента
						- Если нет, то возвращаем ошибку

			# Передан только ip
				- Проверяем, что передан валидный ip
			  		- Если все в порядке, то выполняем grpc Ping, чтобы удостовериться, что на сервере установлено и запущенно наше ПО
						- Если Ping прошел успешно, то регистрируем ноду-агента
						- Если нет, то возвращаем ошибку

					- Если ip не валиден, то возвращаем ошибку

			# Передан ip + домен
				- Получаем ip из А записей домена
				- Проверяем является ли переданный ip одним из ip в А записях домена
					- Если все в порядке, то выполняем grpc Ping, чтобы удостовериться, что на сервере установлено и запущенно наше ПО
						- Если Ping прошел успешно, то регистрируем ноду-агента
						- Если нет, то возвращаем ошибку

					- Если ip нет, то возвращаем ошибку
	*/

	n := models.NodeAgent{
		Ip:     r.Ip,
		Domain: r.Domain,
	}

	if n.Domain == "" && n.Ip == "" {
		resp := &protoManager.CreateNodeResponse{
			Result: &protoManager.CreateNodeResponse_Error_{
				Error: &protoManager.CreateNodeResponse_Error{
					Message: "Neither domain nor ip address was sent",
					Code:    5,
				},
			},
		}
		md.Append("x-http-code", "400")
		grpc.SendHeader(ctx, md)
		return resp, nil
	}

	if n.Domain != "" {
		reg, err := regexp.Compile(`^([A-Za-zА-Яа-я0-9-]{1,63}\.)+[A-Za-zА-Яа-я0-9]{2,6}$`)
		if err != nil {
			s.logger.WhithErrorFields(err).Error("failed to compile pattern for regular expression ")
			md.Append("x-http-code", "500")
			grpc.SendHeader(ctx, md)
			return internalError, nil
		}

		ok := reg.MatchString(n.Domain)
		if !ok {
			resp := &protoManager.CreateNodeResponse{
				Result: &protoManager.CreateNodeResponse_Error_{
					Error: &protoManager.CreateNodeResponse_Error{
						Message: "Specified domain is not valid",
						Code:    4,
					},
				},
			}
			md.Append("x-http-code", "400")
			grpc.SendHeader(ctx, md)
			return resp, nil
		}

		len := utf8.RuneCountInString(n.Domain)
		if len > 253 {
			resp := &protoManager.CreateNodeResponse{
				Result: &protoManager.CreateNodeResponse_Error_{
					Error: &protoManager.CreateNodeResponse_Error{
						Message: "Specified domain is too long",
						Code:    4,
					},
				},
			}
			md.Append("x-http-code", "400")
			grpc.SendHeader(ctx, md)
			return resp, nil
		}

		// Проверяем существование домена и получаем его ip адрес
		resolvedIPs, err := net.LookupHost(n.Domain)
		if err != nil {
			if e, ok := err.(*net.DNSError); ok && e.IsNotFound {
				resp := &protoManager.CreateNodeResponse{
					Result: &protoManager.CreateNodeResponse_Error_{
						Error: &protoManager.CreateNodeResponse_Error{
							Message: fmt.Sprintf("Failed to get domain information %s", n.Domain),
							Code:    4,
						},
					},
				}
				md.Append("x-http-code", "200")
				grpc.SendHeader(ctx, md)
				return resp, nil
			}
			s.logger.WhithErrorFields(err).Errorf("Unable to find ip for domain: %s", n.Domain)
			md.Append("x-http-code", "500")
			grpc.SendHeader(ctx, md)
			return internalError, nil
		}

		if n.Ip == "" {
			n.Ip = resolvedIPs[0]
		} else {
			// Проверяем является ли переданный ip одним из ip из ресурсных записей домена
			var ok bool
			for _, ip := range resolvedIPs {
				if ip == n.Ip {
					ok = true
				}
			}

			if r := net.ParseIP(n.Ip); r == nil {
				resp := &protoManager.CreateNodeResponse{
					Result: &protoManager.CreateNodeResponse_Error_{
						Error: &protoManager.CreateNodeResponse_Error{
							Message: "Specified ip address is not valid",
							Code:    3,
						},
					},
				}
				md.Append("x-http-code", "400")
				grpc.SendHeader(ctx, md)
				return resp, nil
			}

			if !ok && n.Ip != "" {
				resp := &protoManager.CreateNodeResponse{
					Result: &protoManager.CreateNodeResponse_Error_{
						Error: &protoManager.CreateNodeResponse_Error{
							Message: "Specified ip address and ip address from domain resource records are different",
							Code:    5,
						},
					},
				}
				md.Append("x-http-code", "400")
				grpc.SendHeader(ctx, md)
				return resp, nil
			}
		}
	}

	_, err := s.Ping(n.Ip, s.cfg.Grpc.AgentsPort, s.cfg.Grpc.PingTimeout)
	if err != nil {
		resp := &protoManager.CreateNodeResponse{
			Result: &protoManager.CreateNodeResponse_Error_{
				Error: &protoManager.CreateNodeResponse_Error{
					Message: "Failed to connect to agent node",
					Code:    2,
				},
			},
		}
		md.Append("x-http-code", "200")
		grpc.SendHeader(ctx, md)
		return resp, nil
	}

	isExistByDomain, err := s.repo.Nodes.CheckNodeExistenceByDomain(n.Domain)
	if err != nil {
		s.logger.WhithErrorFields(err).Errorf("failed to add node %v to monitoring", n)
		md.Append("x-http-code", "500")
		grpc.SendHeader(ctx, md)
		return internalError, nil
	}
	isExistByIP, err := s.repo.Nodes.CheckNodeExistenceByIP(n.Ip)
	if err != nil {
		s.logger.WhithErrorFields(err).Errorf("failed to add node %v to monitoring", n)
		md.Append("x-http-code", "500")
		grpc.SendHeader(ctx, md)
		return internalError, nil
	}

	if (isExistByDomain && n.Domain != "") || isExistByIP {
		resp := &protoManager.CreateNodeResponse{
			Result: &protoManager.CreateNodeResponse_Error_{
				Error: &protoManager.CreateNodeResponse_Error{
					Message: "Node agent is already exist in monitoring",
					Code:    1,
				},
			},
		}
		md.Append("x-http-code", "200")
		grpc.SendHeader(ctx, md)
		return resp, nil
	}

	_, err = s.repo.AddNode(n.Ip, n.Domain)
	if err != nil {
		s.logger.WhithErrorFields(err).Errorf("failed to add node %v to monitoring", n)
		md.Append("x-http-code", "500")
		grpc.SendHeader(ctx, md)
		return internalError, nil
	}

	node, err := s.repo.GetNodeByIP(n.Ip)
	if err != nil {
		s.logger.WhithErrorFields(err).Errorf("failed to get node with ip %s from database ", n.Ip)
		md.Append("x-http-code", "500")
		grpc.SendHeader(ctx, md)
		return internalError, nil
	}

	md.Append("x-http-code", "200")
	grpc.SendHeader(ctx, md)
	resp := &protoManager.CreateNodeResponse{
		Result: &protoManager.CreateNodeResponse_NodeAgent{
			NodeAgent: &protoManager.NodeAgent{
				Id:     int64(node.Id),
				Ip:     node.Ip,
				Domain: node.Domain,
			},
		},
	}

	return resp, nil
}

func (s *Server) DeleteNode(ctx context.Context, r *protoManager.DeleteNodeRequest) (*protoManager.DeleteNodeResponse, error) {
	internalError := &protoManager.DeleteNodeResponse{
		Result: &protoManager.DeleteNodeResponse_Error_{
			Error: &protoManager.DeleteNodeResponse_Error{
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

	isExist, err := s.repo.Nodes.CheckNodeExistenceByID(int(r.Id))
	if err != nil {
		s.logger.WhithErrorFields(err).Errorf("failed to check if node with id %s exists in the database ", r.Id)
		md.Append("x-http-code", "500")
		grpc.SendHeader(ctx, md)
		return internalError, nil
	}

	if !isExist {
		resp := &protoManager.DeleteNodeResponse{
			Result: &protoManager.DeleteNodeResponse_Error_{
				Error: &protoManager.DeleteNodeResponse_Error{
					Message: fmt.Sprintf("Agent nodes with id %d were not found in monitoring", r.Id),
					Code:    1,
				},
			},
		}
		md.Append("x-http-code", "404")
		grpc.SendHeader(ctx, md)
		return resp, nil
	}

	_, err = s.repo.DeleteNode(int(r.Id))
	if err != nil {
		s.logger.WhithErrorFields(err).Errorf("failed to remove node with id %s from the database", r.Id)
		md.Append("x-http-code", "500")
		grpc.SendHeader(ctx, md)
		return internalError, nil
	}

	resp := &protoManager.DeleteNodeResponse{
		Result: &protoManager.DeleteNodeResponse_Success_{
			Success: &protoManager.DeleteNodeResponse_Success{},
		},
	}

	md.Append("x-http-code", "200")
	grpc.SendHeader(ctx, md)
	return resp, nil
}

func (s *Server) GetNodes(ctx context.Context, r *protoManager.GetNodesRequest) (*protoManager.GetNodesResponse, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		s.logger.WhithErrorFields(fmt.Errorf("failed to get metadata from incomming context")).Error()
		md.Append("x-http-code", "500")
		grpc.SendHeader(ctx, md)
		resp := &protoManager.GetNodesResponse{
			Result: &protoManager.GetNodesResponse_Error_{
				Error: &protoManager.GetNodesResponse_Error{
					Message: "An unexpected error has occurred",
					Code:    0,
				},
			},
		}

		return resp, nil
	}

	nodes, err := s.repo.ListAllNodes()
	if err != nil {
		s.logger.WhithErrorFields(err).Error("Failed to get a list of all monitored nodes from the database ")
		resp := &protoManager.GetNodesResponse{
			Result: &protoManager.GetNodesResponse_Error_{
				Error: &protoManager.GetNodesResponse_Error{
					Message: "An unexpected error has occurred",
					Code:    0,
				},
			},
		}

		md.Append("x-http-code", "500")
		grpc.SendHeader(ctx, md)
		return resp, nil
	}

	node := []*protoManager.NodeAgent{}

	for _, v := range nodes {
		node = append(node, &protoManager.NodeAgent{

			Domain: v.Domain,
			Id:     int64(v.Id),
			Ip:     v.Ip,
		})
	}

	resp := &protoManager.GetNodesResponse{
		Result: &protoManager.GetNodesResponse_ListNodes_{
			ListNodes: &protoManager.GetNodesResponse_ListNodes{
				NodeAgent: node,
			},
		},
	}

	md.Append("x-http-code", "200")
	grpc.SendHeader(ctx, md)
	return resp, nil
}

func (s *Server) RebootNode(ctx context.Context, r *protoManager.RebootNodeRequest) (*protoManager.RebootNodeResponse, error) {
	internalError := &protoManager.RebootNodeResponse{
		Result: &protoManager.RebootNodeResponse_Error_{
			Error: &protoManager.RebootNodeResponse_Error{
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

	isExist, err := s.repo.Nodes.CheckNodeExistenceByID(int(r.Id))
	if err != nil {
		s.logger.WhithErrorFields(err).Errorf("failed to check if node with id %s exists in the database", r.Id)
		md.Append("x-http-code", "500")
		grpc.SendHeader(ctx, md)
		return internalError, nil
	}

	if !isExist {
		resp := &protoManager.RebootNodeResponse{
			Result: &protoManager.RebootNodeResponse_Error_{
				Error: &protoManager.RebootNodeResponse_Error{
					Message: fmt.Sprintf("Agent nodes with id %d were not found in monitoring", r.Id),
					Code:    1,
				},
			},
		}
		md.Append("x-http-code", "404")
		grpc.SendHeader(ctx, md)
		return resp, nil
	}

	node, err := s.repo.GetNodeByID(int(r.Id))
	if err != nil {
		s.logger.WhithErrorFields(err).Errorf("failed to get node with id %s from database", r.Id)
		md.Append("x-http-code", "500")
		grpc.SendHeader(ctx, md)
		return internalError, nil
	}
	_, err = s.Ping(node.Ip, s.cfg.Grpc.AgentsPort, s.cfg.Grpc.PingTimeout)
	if err != nil {
		resp := &protoManager.RebootNodeResponse{
			Result: &protoManager.RebootNodeResponse_Error_{
				Error: &protoManager.RebootNodeResponse_Error{
					Message: fmt.Sprintf("Failed to connect to agent node with id %d", r.Id),
					Code:    2,
				},
			},
		}
		md.Append("x-http-code", "200")
		grpc.SendHeader(ctx, md)
		return resp, nil
	}

	_, err = s.Reboot(node.Ip, s.cfg.Grpc.AgentsPort)
	if err != nil {
		s.logger.WhithErrorFields(err).Errorf("Failed to reboot agent node with id %d", r.Id)
		md.Append("x-http-code", "500")
		grpc.SendHeader(ctx, md)
		return internalError, nil
	}
	md.Append("x-http-code", "200")
	grpc.SendHeader(ctx, md)

	resp := &protoManager.RebootNodeResponse{
		Result: &protoManager.RebootNodeResponse_Success_{
			Success: &protoManager.RebootNodeResponse_Success{
				Message: fmt.Sprintf("Agent node with id %d will be restarted in 1 minute", node.Id),
				Node: &protoManager.NodeAgent{
					Id:     int64(node.Id),
					Ip:     node.Ip,
					Domain: node.Domain,
				},
			},
		},
	}
	return resp, nil
}
