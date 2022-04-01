package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/nedostupno/zinaida/internal/config"
	"github.com/nedostupno/zinaida/internal/delivery/grpc/manager"
	api "github.com/nedostupno/zinaida/internal/delivery/rest"
	"github.com/nedostupno/zinaida/internal/repository"
	"github.com/nedostupno/zinaida/logger"
	"github.com/sirupsen/logrus"
)

func main() {
	log := logger.GetLogger()

	cfg, err := config.GetManagerConfig()
	if err != nil {
		log.WhithErrorFields(err).Fatal("failed to get configuration")
	}
	db, err := repository.NewSqliteDB()
	if err != nil {
		log.WhithErrorFields(err).Fatal("failed to create database connection")
	}
	defer db.Close()

	log.SetLevel(logrus.Level(cfg.LogLevel))

	repo := repository.NewRepository(db)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	srv := manager.NewManagerServer(repo, log, cfg)
	go srv.RunServer(ctx)

	a := api.GetApi(repo, log, cfg, srv)
	a.InitRouter()
	a.Run(ctx)
}
