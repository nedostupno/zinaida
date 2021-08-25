package delivery

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/nedostupno/zinaida/internal/auth"
	"github.com/nedostupno/zinaida/internal/auth/utils"
	models "github.com/nedostupno/zinaida/internal/models"
)

func GetMap() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Handler GetMap not implemented"))
	})
}

func GetNodes(a *Api) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nodes, err := a.Repo.ListAllNodes()
		if err != nil {
			m := utils.Message(false, err.Error())
			utils.Respond(w, m)
			return
		}
		w.Write([]byte(fmt.Sprintf("Список нод Агентов: %v", nodes)))
	})
}

func CreateNode(a *Api) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var n models.NodeAgent
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&n); err != nil {
			m := utils.Message(false, "Incorrect request data")
			utils.Respond(w, m)
			return
		}
		defer r.Body.Close()

		result, err := a.Repo.AddNode(n.Ip, n.Domain)
		if err != nil {
			m := utils.Message(false, err.Error())
			utils.Respond(w, m)
			return
		}
		w.Write([]byte(fmt.Sprintf("НодаАгент успешно зарегистрирована: %v", result)))
	})
}

func GetNodeInfo(a *Api) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id := vars["id"]

		node, err := a.Repo.GetNodeByID(id)
		if err != nil {
			m := utils.Message(false, err.Error())
			utils.Respond(w, m)
		}

		w.Write([]byte(fmt.Sprintf("%v", node)))
	})
}

func DeleteNode(a *Api) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id := vars["id"]

		ifExist, err := a.Repo.Nodes.CheckNodeExistenceByID(id)
		if err != nil {
			m := utils.Message(false, err.Error())
			utils.Respond(w, m)
		}

		if ifExist {
			_, err = a.Repo.DeleteNode(id)
			if err != nil {
				m := utils.Message(false, err.Error())
				utils.Respond(w, m)
			}

			w.Write([]byte(fmt.Sprintf("Нода-агент с id %s успешно удалена из мониторинга", id)))
		}

		w.Write([]byte(fmt.Sprintf("Нода-агент с id %s не находится в мониторинге. ", id)))
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
		username := os.Getenv("LOGIN")
		password := os.Getenv("PASSWORD")

		fmt.Println(username, password, "sssssssssss")

		var creds models.Credential

		err := json.NewDecoder(r.Body).Decode(&creds)
		if err != nil {
			w.Write([]byte(fmt.Sprintf("Augh.... err in decode: %v", err)))
		}
		defer r.Body.Close()

		if creds.Username == username && creds.Password == password {
			token, err := auth.GenerateJWT()
			if err != nil {
				w.Write([]byte(fmt.Sprintf("Augh.... err generateJWT: %+v", err)))
			}

			msg := utils.Message(true, token)

			utils.Respond(w, msg)
		} else {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Augh.... incorect login or password"))
		}
	})
}
