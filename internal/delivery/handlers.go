package delivery

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/nedostupno/zinaida/internal/auth"
	"github.com/nedostupno/zinaida/internal/auth/utils"
	"github.com/nedostupno/zinaida/internal/delivery/grpc"
	models "github.com/nedostupno/zinaida/internal/models"
	"github.com/nedostupno/zinaida/traceroute"
)

func GetMap(a *Api) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ips, err := a.Repo.GetAllNodesIP()
		if err != nil {
			m := utils.Message(false, err.Error())
			utils.Respond(w, m)
			return
		}
		fmt.Println(ips)

		traceMap, err := traceroute.Trace(ips)
		if err != nil {
			m := utils.Message(false, err.Error())
			utils.Respond(w, m)
			return
		}

		fmt.Println(traceMap)
		jsnResp, err := json.Marshal(traceMap)
		if err != nil {
			m := utils.Message(false, err.Error())
			utils.Respond(w, m)
		}
		w.Write([]byte(string(jsnResp)))
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
		jsnResp, err := json.Marshal(nodes)
		if err != nil {
			m := utils.Message(false, err.Error())
			utils.Respond(w, m)
		}
		w.Write([]byte(string(jsnResp)))
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

		_, err := a.Repo.AddNode(n.Ip, n.Domain)
		if err != nil {
			m := utils.Message(false, err.Error())
			utils.Respond(w, m)
			return
		}

		node, err := a.Repo.GetNodeByIP(n.Ip)
		if err != nil {
			m := utils.Message(false, err.Error())
			utils.Respond(w, m)
		}

		w.Write([]byte(fmt.Sprintf("НодаАгент успешно зарегистрирована: %v", node)))
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
		jsnResp, err := json.Marshal(node)
		if err != nil {
			m := utils.Message(false, err.Error())
			utils.Respond(w, m)
		}
		w.Write([]byte(string(jsnResp)))
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
		} else {
			w.Write([]byte(fmt.Sprintf("Нода-агент с id %s не находится в мониторинге. ", id)))
		}
	})
}

func GetStat(a *Api) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id := vars["id"]
		node, err := a.Repo.GetNodeByID(id)
		if err != nil {
			m := utils.Message(false, err.Error())
			utils.Respond(w, m)
		}
		resp, err := grpc.GetStat(node.Ip)
		if err != nil {
			m := utils.Message(false, err.Error())
			utils.Respond(w, m)
		}
		jsnResp, err := json.Marshal(resp)
		if err != nil {
			m := utils.Message(false, err.Error())
			utils.Respond(w, m)
		}
		w.Write([]byte(string(jsnResp)))
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
