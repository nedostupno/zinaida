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

type Server struct {
	repo   *repository.Repository
	logger *logger.Logger
	cfg    *config.ManagerConfig
	manager.UnimplementedManagerServer
}

func NewManagerServer(repo *repository.Repository, logger *logger.Logger, cfg *config.ManagerConfig) *Server {
	return &Server{
		repo:                       repo,
		logger:                     logger,
		cfg:                        cfg,
		UnimplementedManagerServer: manager.UnimplementedManagerServer{},
	}
}

func (s *Server) RunServer() {
	srv := grpc.NewServer()
	port := s.cfg.Grpc.Port
	ip := s.cfg.Grpc.Ip

	lis, err := net.Listen("tcp", fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		s.logger.WhithErrorFields(err).Fatalf("Не удалось начать прослушивать адрес %s:%d", ip, port)
	}

	manager.RegisterManagerServer(srv, s)

	if err := srv.Serve(lis); err != nil {
		s.logger.WhithErrorFields(err).Fatalf("Не удалось начать обслуживать grpc сервер")
	}
}