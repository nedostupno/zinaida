package agent

import (
	"fmt"
	"net"

	"github.com/nedostupno/zinaida/internal/config"
	"github.com/nedostupno/zinaida/logger"
	"github.com/nedostupno/zinaida/proto/agent"
	"google.golang.org/grpc"
)

type server struct {
	agent.UnimplementedAgentServer
}

func RunServer(cfg *config.AgentConfig, log *logger.Logger) {
	srv := grpc.NewServer()
	port := cfg.Agent.Port
	ip := cfg.Agent.Ip

	lis, err := net.Listen("tcp", fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		log.WhithErrorFields(err).Fatalf("failed to listen on %s:%d", ip, port)
	}

	var s server
	agent.RegisterAgentServer(srv, s)

	err = Registrate(cfg)
	if err != nil {
		log.WhithErrorFields(err).Fatal("Не удалось автоматически зарегистрироваться у ноды менеджера")
	}
	if err := srv.Serve(lis); err != nil {
		log.WhithErrorFields(err).Fatalf("failed to serve with listen: %v", lis)
	}
}
