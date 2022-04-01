package delivery

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/nedostupno/zinaida/internal/config"
	"github.com/nedostupno/zinaida/internal/delivery/grpc/manager"
	"github.com/nedostupno/zinaida/internal/repository"
	"github.com/nedostupno/zinaida/logger"
)

type api struct {
	repo   *repository.Repository
	logger *logger.Logger
	cfg    *config.ManagerConfig
	grpc   *manager.Server
	srv    *http.Server
}

func (a *api) InitRouter() {
	router := mux.NewRouter()
	router.HandleFunc("/api/map/", a.GetMap).Methods("GET")
	router.HandleFunc("/api/nodes/", a.GetNodes).Methods("GET")
	router.HandleFunc("/api/nodes/", a.CreateNode).Methods("POST")
	router.HandleFunc("/api/nodes/{id:[0-9]+}", a.GetNodeInfo).Methods("GET")
	router.HandleFunc("/api/nodes/{id:[0-9]+}", a.DeleteNode).Methods("DELETE")
	router.HandleFunc("/api/nodes/{id:[0-9]+}/stat/", a.GetStat).Methods("GET")
	router.HandleFunc("/api/nodes/{id:[0-9]+}/reboot/", a.RebootNode).Methods("GET")
	router.HandleFunc("/api/login/", a.Login).Methods("POST")
	router.HandleFunc("/api/refresh/", a.Refresh).Methods("POST")

	a.srv.Handler = router
	router.Use(a.LoggingMidleware, a.JwtAuthenticationMiddleware)
}

func (a *api) Run(ctx context.Context) {
	addr := fmt.Sprintf("%s:%d", a.cfg.Rest.Ip, a.cfg.Rest.Port)
	a.srv.Addr = addr

	go func() {
		if err := a.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			a.logger.WhithErrorFields(err).Fatalf("failed to listen on %s", addr)
		}
	}()

	a.logger.Debugf("rest api server start listening on %s", addr)
	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Duration(a.cfg.Rest.ShutdownTimeout)*time.Millisecond)
	defer cancel()

	if err := a.srv.Shutdown(shutdownCtx); err != nil {
		a.logger.WhithErrorFields(err).Fatal("failed graceful shutdown rest api server")
	}

	a.logger.Debug("rest api server success graceful shutdown")
	<-shutdownCtx.Done()
}

func GetApi(repo *repository.Repository, log *logger.Logger, cfg *config.ManagerConfig, grpcServer *manager.Server) *api {
	return &api{
		repo:   repo,
		logger: log,
		cfg:    cfg,
		grpc:   grpcServer,
		srv:    &http.Server{},
	}
}
