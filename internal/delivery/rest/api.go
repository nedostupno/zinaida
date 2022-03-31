package delivery

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/nedostupno/zinaida/internal/config"
	"github.com/nedostupno/zinaida/internal/delivery/grpc/manager"
	"github.com/nedostupno/zinaida/internal/repository"
	"github.com/nedostupno/zinaida/logger"
)

type api struct {
	router *mux.Router
	repo   *repository.Repository
	logger *logger.Logger
	cfg    *config.ManagerConfig
	grpc   *manager.Server
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

	a.router = router

	router.Use(a.LoggingMidleware, a.JwtAuthenticationMiddleware)
}

func (a *api) Run() {
	addr := fmt.Sprintf("%s:%d", a.cfg.Rest.Ip, a.cfg.Rest.Port)

	if err := http.ListenAndServe(addr, a.router); err != nil {
		a.logger.WhithErrorFields(err).Fatalf("failed to listen on %s", addr)
	}
}

func GetApi(repo *repository.Repository, log *logger.Logger, cfg *config.ManagerConfig, grpcServer *manager.Server) *api {
	return &api{
		router: &mux.Router{},
		repo:   repo,
		logger: log,
		cfg:    cfg,
		grpc:   grpcServer,
	}
}
