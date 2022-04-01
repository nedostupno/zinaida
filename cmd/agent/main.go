package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/nedostupno/zinaida/internal/config"
	"github.com/nedostupno/zinaida/internal/delivery/grpc/agent"
	"github.com/nedostupno/zinaida/logger"
	"github.com/sirupsen/logrus"
)

func main() {
	log := logger.GetLogger()

	cfg, err := config.GetAgentConfig()
	if err != nil {
		log.WhithErrorFields(err).Fatal("failed to get configuration")
	}
	log.SetLevel(logrus.Level(cfg.LogLevel))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	srv := agent.NewAgentServer(log, cfg)
	srv.RunServer(ctx)
}
