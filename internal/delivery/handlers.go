package delivery

import (
	"net/http"
)

func GetMap() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Handler GetMap not implemented"))
	})
}

func GetNodes() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Handler GetNodes not implemented"))
	})
}

func CreateNode() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Handler CreateNode not implemented"))
	})
}

func GetNodeInfo() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		w.Write([]byte("Handler GetNodeInfo not implemented"))
	})
}

func DeleteNode() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Handler DeleteNode not implemented"))
	})
}

func GetStat() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Handler GetStat not implemented"))
	})
}

func RebootNode() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Handler RebootNode not implemented"))
	})
}

func Login() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Handler Login not implemented"))
	})
}
