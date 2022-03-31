package main

import (
	"github.com/nedostupno/zinaida/internal/config"
	"github.com/nedostupno/zinaida/internal/delivery/grpc/agent"
	"github.com/nedostupno/zinaida/logger"
)

func main() {
	log := logger.GetLogger()

	cfg, err := config.GetAgentConfig()
	if err != nil {
		log.WhithErrorFields(err).Fatal("failed to get configuration")
	}

	srv := agent.NewAgentServer(log, cfg)
	srv.RunServer()
}
