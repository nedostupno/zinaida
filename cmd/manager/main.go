package main

import (
	"github.com/nedostupno/zinaida/internal/config"
	"github.com/nedostupno/zinaida/internal/delivery/grpc/manager"
	api "github.com/nedostupno/zinaida/internal/delivery/rest"
	"github.com/nedostupno/zinaida/internal/repository"
	"github.com/nedostupno/zinaida/logger"
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

	repo := repository.NewRepository(db)

	srv := manager.NewManagerServer(repo, log, cfg)
	go srv.RunServer()

	a := api.GetApi(repo, log, cfg, srv)
	a.InitRouter()
	a.Run()
}
