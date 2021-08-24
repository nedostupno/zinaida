package main

import (
	"log"

	api "github.com/nedostupno/zinaida/internal/delivery"
	"github.com/nedostupno/zinaida/internal/delivery/grpc"
	"github.com/nedostupno/zinaida/internal/repository"
)

func main() {

	db, err := repository.NewSqliteDB()
	if err != nil {
		log.Fatalln(err)
	}
	repo := repository.NewRepository(db)
	go grpc.RunServer(repo)

	a := api.Api{}
	a.Repo = repo

	a.Init()
	a.Run(":8000")

}
