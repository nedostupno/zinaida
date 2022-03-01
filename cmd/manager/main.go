package main

import (
	api "github.com/nedostupno/zinaida/internal/delivery"
	"github.com/nedostupno/zinaida/internal/delivery/grpc"
	"github.com/nedostupno/zinaida/internal/repository"
	"github.com/nedostupno/zinaida/logger"
)

func main() {
	log := logger.GetLogger()

	db, err := repository.NewSqliteDB()
	if err != nil {
		log.WhithErrorFields(err).Fatal("не удалось создать подключение к базе данных")
	}
	repo := repository.NewRepository(db)
	go grpc.RunServer(repo, log)

	a := api.GetApi(repo, log)
	a.InitRouter()
	a.Run(":8000")
}
