package manager

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/nedostupno/zinaida/internal/config"
	"github.com/nedostupno/zinaida/internal/repository"
	"github.com/nedostupno/zinaida/logger"
	"github.com/nedostupno/zinaida/proto/protoManager"
	"github.com/tmc/grpc-websocket-proxy/wsproxy"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/protojson"
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
	srv := grpc.NewServer(
		grpc_middleware.WithUnaryServerChain(s.JwtAuthenticationInterceptor),
		grpc_middleware.WithStreamServerChain(s.StreamServerJWTInterceptor),
	)

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
	s.logger.Debugf("grpc server start serve on %s:%d", ip, port)
	<-ctx.Done()

	srv.GracefulStop()
	s.logger.Debug("grpc server success graceful shutdown")
}

func (s *Server) RunGatewayServer(ctx context.Context) {
	port := s.cfg.Grpc.Port
	ip := s.cfg.Grpc.Ip

	addr := fmt.Sprintf("%s:%d", ip, port)

	customMarshaller := &runtime.JSONPb{
		MarshalOptions: protojson.MarshalOptions{
			EmitUnpopulated: true, // disable 'omitempty'
		},
	}

	mux := runtime.NewServeMux(
		runtime.WithMarshalerOption(runtime.MIMEWildcard, customMarshaller),
		runtime.WithForwardResponseOption(s.httpResponseModifier),
	)

	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	err := protoManager.RegisterManagerHandlerFromEndpoint(ctx, mux, addr, opts)
	if err != nil {
		s.logger.WhithErrorFields(err).Fatalln("Failed to register manager handler")
	}

	server := http.Server{
		// TODO: заменить addr на адрес для rest api
		Addr:    ":8080",
		Handler: s.LoggingMidleware(wsproxy.WebsocketProxy(mux)),
	}

	go func() {
		err = server.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			s.logger.WhithErrorFields(err).Fatalln("Failed to serve grpc-gateway server")
		}
	}()
	s.logger.Debugf("grpc gateway server start listening on %s", server.Addr)

	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Duration(s.cfg.Rest.ShutdownTimeout)*time.Millisecond)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		s.logger.WhithErrorFields(err).Fatal("failed graceful shutdown grpc gateway server")
	}
	s.logger.Debug("grpc gateway server success graceful shutdown")
	<-shutdownCtx.Done()
}
