package manager

import (
	"context"
	"fmt"
	"net"

	"github.com/nedostupno/zinaida/internal/config"
	"github.com/nedostupno/zinaida/internal/repository"
	"github.com/nedostupno/zinaida/logger"
	"github.com/nedostupno/zinaida/proto/protoManager"
	"google.golang.org/grpc"
)

type Server struct {
	repo   *repository.Repository
	logger *logger.Logger
	cfg    *config.ManagerConfig
	protoManager.UnimplementedManagerServer
}

func NewManagerServer(repo *repository.Repository, logger *logger.Logger, cfg *config.ManagerConfig) *Server {
	return &Server{
		repo:                       repo,
		logger:                     logger,
		cfg:                        cfg,
		UnimplementedManagerServer: protoManager.UnimplementedManagerServer{},
	}
}

func (s *Server) RunServer(ctx context.Context) {
	srv := grpc.NewServer()
	port := s.cfg.Grpc.Port
	ip := s.cfg.Grpc.Ip

	lis, err := net.Listen("tcp", fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		s.logger.WhithErrorFields(err).Fatalf("failed to listen on %s:%d", ip, port)
	}

	protoManager.RegisterManagerServer(srv, s)

	go func() {
		if err := srv.Serve(lis); err != nil {
			s.logger.WhithErrorFields(err).Fatalf("failed to server grpc server")
		}
	}()

	<-ctx.Done()

	srv.GracefulStop()
}
