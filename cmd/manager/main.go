package main

import (
	"github.com/nedostupno/zinaida/internal/config"
	api "github.com/nedostupno/zinaida/internal/delivery"
	"github.com/nedostupno/zinaida/internal/delivery/manager"
	"github.com/nedostupno/zinaida/internal/repository"
	"github.com/nedostupno/zinaida/logger"
)

func main() {
	log := logger.GetLogger()

	cfg, err := config.GetManagerConfig()
	if err != nil {
		log.WhithErrorFields(err).Fatal("не удалось получить конфигурацию")
	}
	db, err := repository.NewSqliteDB()
	if err != nil {
		log.WhithErrorFields(err).Fatal("не удалось создать подключение к базе данных")
	}
	defer db.Close()

	repo := repository.NewRepository(db)
	go manager.RunServer(repo, log, cfg)

	a := api.GetApi(repo, log, cfg)
	a.InitRouter()
	a.Run()
}
