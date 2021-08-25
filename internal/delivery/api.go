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
	router.Handle("/api/map/", GetMap()).Methods("GET")
	router.Handle("/api/nodes/", GetNodes(a)).Methods("GET")
	router.Handle("/api/nodes/", CreateNode(a)).Methods("POST")
	router.Handle("/api/nodes/{id:[0-9]+}", GetNodeInfo(a)).Methods("GET")
	router.Handle("/api/nodes/{id:[0-9]+}", DeleteNode()).Methods("DELETE")
	router.Handle("/api/nodes/{id:[0-9]+}/stat/", GetStat()).Methods("GET")
	router.Handle("/api/nodes/{id:[0-9]+}/reboot/", RebootNode()).Methods("GET")
	router.Handle("/api/login/", Login()).Methods("POST")

	router.Use(auth.JwtAuthentication)
	a.Router = router
}

func (a *Api) Run(addr string) {
	http.ListenAndServe(addr, handlers.CombinedLoggingHandler(os.Stdout, a.Router))
}
