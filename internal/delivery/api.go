package delivery

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/nedostupno/zinaida/internal/repository"
	"github.com/nedostupno/zinaida/logger"
)

// TODO: сделать поля структуры недоступными из других пакетов напрямую
type Api struct {
	Router *mux.Router
	Repo   *repository.Repository
	Logger *logger.Logger
}

func (a *Api) InitRouter() {
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

	a.Router = router

	router.Use(a.LoggingMidleware, a.JwtAuthenticationMiddleware)
}

func (a *Api) Run(addr string) {
	//TODO: обработать ошибку
	http.ListenAndServe(addr, a.Router)
}

func GetApi(repo *repository.Repository, log *logger.Logger) *Api {
	return &Api{
		Router: &mux.Router{},
		Repo:   repo,
		Logger: log,
	}
}
