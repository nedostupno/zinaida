package manager

import (
	"fmt"
	"net"

	"github.com/nedostupno/zinaida/internal/config"
	"github.com/nedostupno/zinaida/internal/repository"
	"github.com/nedostupno/zinaida/logger"
	"github.com/nedostupno/zinaida/proto/manager"
	"google.golang.org/grpc"
)

type server struct {
	repo   *repository.Repository
	logger *logger.Logger
	manager.UnimplementedManagerServer
}

func RunServer(repo *repository.Repository, log *logger.Logger, cfg *config.ManagerConfig) {
	srv := grpc.NewServer()
	port := cfg.Grpc.Port
	ip := cfg.Grpc.Ip

	lis, err := net.Listen("tcp", fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		log.WhithErrorFields(err).Fatalf("Не удалось начать прослушивать адрес %s:%d", ip, port)
	}

	var s server
	s.logger = log
	s.repo = repo
	manager.RegisterManagerServer(srv, s)

	if err := srv.Serve(lis); err != nil {
		log.WhithErrorFields(err).Fatalf("Не удалось начать обслуживать grpc сервер")
	}
}
