package agent

import (
	"fmt"
	"net"

	"github.com/nedostupno/zinaida/internal/config"
	"github.com/nedostupno/zinaida/logger"
	"github.com/nedostupno/zinaida/proto/protoAgent"
	"golang.org/x/net/context"
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

func (s *server) RunServer(ctx context.Context) {
	srv := grpc.NewServer()
	port := s.cfg.Agent.Port
	ip := s.cfg.Agent.Ip

	lis, err := net.Listen("tcp", fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		s.log.WhithErrorFields(err).Fatalf("failed to listen on %s:%d", ip, port)
	}

	protoAgent.RegisterAgentServer(srv, s)

	// Пробуем в отдельной горутиние подключиться к ноде-менеджеру по gRPC и автоматически зарегистрироваться
	go func() {
		err = s.Registrate()
		if err != nil {
			s.log.WhithErrorFields(err).Error("Failed to auto-register when connecting to node manager")
		} else {
			s.log.Debug("the node has successfully registered with the manager ")
		}
	}()

	go func() {
		if err := srv.Serve(lis); err != nil {
			s.log.WhithErrorFields(err).Fatalf("failed to serve with listen: %v", lis)
		}
	}()
	s.log.Debugf("grpc server success start serve on %s:%d", ip, port)

	<-ctx.Done()

	srv.GracefulStop()
	s.log.Debug("grpc server success graceful shutdown")
}
