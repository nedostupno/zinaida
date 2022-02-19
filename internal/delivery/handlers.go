package delivery

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/nedostupno/zinaida/internal/auth"
	"github.com/nedostupno/zinaida/internal/auth/utils"
	"github.com/nedostupno/zinaida/internal/delivery/grpc"
	models "github.com/nedostupno/zinaida/internal/models"
	"github.com/nedostupno/zinaida/traceroute"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

func (a *Api) GetMap(w http.ResponseWriter, r *http.Request) {
	destinations := []string{}

	nodes, _ := a.Repo.ListAllNodes()
	for _, node := range nodes {
		if node.Domain != "" {
			destinations = append(destinations, node.Domain)
		} else {
			destinations = append(destinations, node.Ip)
		}
	}
	conn, _ := upgrader.Upgrade(w, r, nil)
	defer conn.Close()

	hops := make(chan traceroute.Hop, 15)
	go func() {
		defer close(hops)
		for i, domain := range destinations {
			t := traceroute.NewTracer()
			t.Traceroute(i, domain, hops)
		}
	}()

	for hop := range hops {
		if err := conn.WriteJSON(hop); err != nil {
			log.Fatal(err)
		}
	}

}

func (a *Api) GetNodes(w http.ResponseWriter, r *http.Request) {
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
}

func (a *Api) CreateNode(w http.ResponseWriter, r *http.Request) {
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

}

func (a *Api) GetNodeInfo(w http.ResponseWriter, r *http.Request) {
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
}

func (a *Api) DeleteNode(w http.ResponseWriter, r *http.Request) {
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
}

func (a *Api) GetStat(w http.ResponseWriter, r *http.Request) {
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
}

func (a *Api) RebootNode(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Handler RebootNode not implemented"))
}

func (a *Api) Login(w http.ResponseWriter, r *http.Request) {
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
		token, err := auth.GenerateJWTToken(username)
		if err != nil {
			w.Write([]byte(fmt.Sprintf("Augh.... err generateJWT: %+v", err)))
		}

		msg := utils.Message(true, token)

		utils.Respond(w, msg)
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Augh.... incorect login or password"))
	}
}
