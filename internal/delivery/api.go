package delivery

import (
	"net/http"
	"os"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/nedostupno/zinaida/internal/auth"
	"github.com/nedostupno/zinaida/internal/repository"
)

type Api struct {
	Router *mux.Router
	Repo   *repository.Repository
}

func (a *Api) Init() {
	router := mux.NewRouter()
	router.HandleFunc("/api/map/", a.GetMap).Methods("GET")
	router.HandleFunc("/api/nodes/", a.GetNodes).Methods("GET")
	router.HandleFunc("/api/nodes/", a.CreateNode).Methods("POST")
	router.HandleFunc("/api/nodes/{id:[0-9]+}", a.GetNodeInfo).Methods("GET")
	router.HandleFunc("/api/nodes/{id:[0-9]+}", a.DeleteNode).Methods("DELETE")
	router.HandleFunc("/api/nodes/{id:[0-9]+}/stat/", a.GetStat).Methods("GET")
	router.HandleFunc("/api/nodes/{id:[0-9]+}/reboot/", a.RebootNode).Methods("GET")
	router.HandleFunc("/api/login/", a.Login).Methods("POST")

	router.Use(auth.JwtAuthentication)
	a.Router = router
}

func (a *Api) Run(addr string) {
	http.ListenAndServe(addr, handlers.CombinedLoggingHandler(os.Stdout, a.Router))
}
