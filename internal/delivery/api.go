package delivery

import (
	"net/http"
	"os"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/nedostupno/zinaida/internal/auth"
)

type Api struct {
	Router *mux.Router
}

func (a *Api) Init() {
	router := mux.NewRouter()
	router.Handle("/api/map/", GetMap()).Methods("GET")
	router.Handle("/api/nodes/", GetNodes()).Methods("GET")
	router.Handle("/api/nodes/", CreateNode()).Methods("POST")
	router.Handle("/api/nodes/{id:[0-9]+}", GetNodeInfo()).Methods("GET")
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
