package agent

import (
	"fmt"
	"net"

	"github.com/nedostupno/zinaida/internal/config"
	"github.com/nedostupno/zinaida/logger"
	"github.com/nedostupno/zinaida/proto/protoAgent"
	"google.golang.org/grpc"
)

type server struct {
	log *logger.Logger
	cfg *config.AgentConfig
	protoAgent.UnimplementedAgentServer
}

func NewAgentServer(log *logger.Logger, cfg *config.AgentConfig) *server {
	return &server{
		log:                      log,
		cfg:                      cfg,
		UnimplementedAgentServer: protoAgent.UnimplementedAgentServer{},
	}
}

func (s *server) RunServer() {
	srv := grpc.NewServer()
	port := s.cfg.Agent.Port
	ip := s.cfg.Agent.Ip

	lis, err := net.Listen("tcp", fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		s.log.WhithErrorFields(err).Fatalf("failed to listen on %s:%d", ip, port)
	}

	protoAgent.RegisterAgentServer(srv, s)

	err = s.Registrate()
	if err != nil {
		s.log.WhithErrorFields(err).Fatal("Не удалось автоматически зарегистрироваться у ноды менеджера")
	}
	if err := srv.Serve(lis); err != nil {
		s.log.WhithErrorFields(err).Fatalf("failed to serve with listen: %v", lis)
	}
}
