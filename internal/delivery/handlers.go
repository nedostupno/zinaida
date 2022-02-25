package delivery

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/golang-jwt/jwt"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/nedostupno/zinaida/internal/auth"
	"github.com/nedostupno/zinaida/internal/auth/utils"
	"github.com/nedostupno/zinaida/internal/delivery/grpc"
	models "github.com/nedostupno/zinaida/internal/models"
	"github.com/nedostupno/zinaida/traceroute"
)

type APIError struct {
	Msg string `json:"error"`
}

func JsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	err := APIError{Msg: msg}
	json.NewEncoder(w).Encode(err)
}

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
		a.Logger.WithErrorFields(r, err).Error("Не удалось получить список всех нод, находящихся в мониторинге, из базы данных")
		JsonError(w, "Произошла непредвиденная ошибка", http.StatusInternalServerError)
		return
	}
	jsnResp, err := json.Marshal(nodes)
	if err != nil {
		a.Logger.WithErrorFields(r, err).Errorf("Не удалось замаршалить []models.NodeAgent %v в json-объект", nodes)
		JsonError(w, "Произошла непредвиденная ошибка", http.StatusInternalServerError)
		return
	}
	w.Write([]byte(string(jsnResp)))
}

func (a *Api) CreateNode(w http.ResponseWriter, r *http.Request) {
	var n models.NodeAgent
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&n); err != nil {
		a.Logger.WithErrorFields(r, err).Error("не удалось декодировать структуру r.Body")
		JsonError(w, "Произошла непредвиденная ошибка", http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	if n.Domain == "" && n.Ip == "" {
		JsonError(w, "Переданы некорректные данные", http.StatusBadRequest)
		return
	}

	// TODO: если передан пустой ip, то необходимо по домену определить ip адрес,
	// и если определить ip не удастся, то ноду в базу данных не добавляем
	_, err := a.Repo.AddNode(n.Ip, n.Domain)
	if err != nil {
		a.Logger.WithErrorFields(r, err).Errorf("не удалось добавить ноду %v в мониторинг", n)
		JsonError(w, "Произошла непредвиденная ошибка", http.StatusInternalServerError)
		return
	}

	node, err := a.Repo.GetNodeByIP(n.Ip)
	if err != nil {
		a.Logger.WithErrorFields(r, err).Errorf("не удалось получить ноду с ip %s из базы данных", n.Ip)
		JsonError(w, "Произошла непредвиденная ошибка", http.StatusInternalServerError)
		return
	}

	w.Write([]byte(fmt.Sprintf("НодаАгент успешно зарегистрирована: %v", node)))
}

func (a *Api) GetNodeInfo(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	//TODO: Добавить проверку существования ноды с указанным id
	node, err := a.Repo.GetNodeByID(id)
	if err != nil {
		a.Logger.WithErrorFields(r, err).Errorf("не удалось получить ноду с id %s из базы данных", id)
		JsonError(w, "Произошла непредвиденная ошибка", http.StatusInternalServerError)
		return
	}
	jsnResp, err := json.Marshal(node)
	if err != nil {
		a.Logger.WithErrorFields(r, err).Errorf("Не удалось замаршалить структуру models.NodeAgent %v в json-объект", node)
		JsonError(w, "Произошла непредвиденная ошибка", http.StatusInternalServerError)
		return
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

	var creds models.Credential

	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		a.Logger.WithErrorFields(r, err).Error("не удалось декодировать структуру r.Body")
		JsonError(w, "Произошла непредвиденная ошибка", http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	exist, err := a.Repo.Users.IsExist(creds.Username)
	if err != nil {
		a.Logger.WithErrorFields(r, err).Error(fmt.Sprintf("не удалось проверить существование пользователя %s в базе данных", creds.Username))
		JsonError(w, "Произошла непредвиденная ошибка", http.StatusInternalServerError)
		return
	}

	if !exist {
		JsonError(w, "Переданы некорреткные данные", http.StatusUnauthorized)
		return
	}

	user, err := a.Repo.Users.Get(creds.Username)
	if err != nil {
		a.Logger.WithErrorFields(r, err).Error(fmt.Sprintf("не удалось получить пользователя %s из базы данных", creds.Username))
		JsonError(w, "Произошла непредвиденная ошибка", http.StatusInternalServerError)
		return
	}

	if creds.Username == user.Username && creds.Password == user.Password {
		jwt, err := auth.GenerateJWTToken(user.Username)
		if err != nil {
			a.Logger.WithErrorFields(r, err).Error(fmt.Sprintf("не удалось сгенерировать JWT access токен для пользователя %s", user.Username))
			JsonError(w, "Произошла непредвиденная ошибка", http.StatusInternalServerError)
			return
		}

		refresh, err := auth.GenerateRefreshToken(user.Username)
		if err != nil {
			a.Logger.WithErrorFields(r, err).Error(fmt.Sprintf("не удалось сгенерировать JWT refresh токен для пользователя %s", user.Username))
			JsonError(w, "Произошла непредвиденная ошибка", http.StatusInternalServerError)
			return
		}

		_, err = a.Repo.Users.UpdateRefreshToken(user.Username, refresh)
		if err != nil {
			a.Logger.WithErrorFields(r, err).Error(fmt.Errorf("не удалось обновить JWT refresh токен в базе для пользователя %s", user.Username))
			JsonError(w, "Произошла непредвиденная ошибка", http.StatusInternalServerError)
			return
		}

		msg := utils.JWTMessage(jwt, refresh)
		utils.Respond(w, msg)
		return
	}
	JsonError(w, "Переданы некорреткные данные", http.StatusUnauthorized)
}

func (a *Api) Refresh(w http.ResponseWriter, r *http.Request) {

	var refresh models.RefreshToken
	err := json.NewDecoder(r.Body).Decode(&refresh)
	if err != nil {
		a.Logger.WithErrorFields(r, err).Error("не удалось декодировать структуру r.Body")
		JsonError(w, "Произошла непредвиденная ошибка", http.StatusInternalServerError)
		return
	}

	if refresh.Token == "" {
		JsonError(w, "Пропущен refresh токен", http.StatusUnauthorized)
		return
	}

	claims := &auth.CustomClaims{}

	token, err := jwt.ParseWithClaims(refresh.Token, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte("Baka-sraka"), nil
	})

	// Ошибка будет выброшена даже в том случае, если токен истек, так что ручные проверки не требуются
	if err != nil || !token.Valid {
		JsonError(w, "Невалидный refresh токен", http.StatusUnauthorized)
		return
	}

	exist, err := a.Repo.Users.IsExist(claims.Username)
	if err != nil {
		a.Logger.WithErrorFields(r, err).Error(fmt.Sprintf("не удалось проверить существование пользователя %s в базе данных", claims.Username))
		JsonError(w, "Произошла непредвиденная ошибка", http.StatusInternalServerError)
		return
	}

	if !exist {
		JsonError(w, "Невалидный refresh токен", http.StatusUnauthorized)
		return
	}

	oldRefreshToken, err := a.Repo.Users.GetRefreshToken(claims.Username)
	if err != nil {
		a.Logger.WithErrorFields(r, err).Error(fmt.Sprintf("не удалось получить refresh токен для пользователя %s из базы данных", claims.Username))
		JsonError(w, "Произошла непредвиденная ошибка", http.StatusInternalServerError)
		return
	}

	if refresh.Token != oldRefreshToken {
		JsonError(w, "Невалидный refrsh токен", http.StatusUnauthorized)
		return
	}

	newJwt, err := auth.GenerateJWTToken(claims.Username)
	if err != nil {
		a.Logger.WithErrorFields(r, err).Error(fmt.Sprintf("не удалось сгенерировать JWT access токен для пользователя %s", claims.Username))
		JsonError(w, "Произошла непредвиденная ошибка", http.StatusInternalServerError)
		return
	}

	newRefresh, err := auth.GenerateRefreshToken(claims.Username)
	if err != nil {
		a.Logger.WithErrorFields(r, err).Error(fmt.Sprintf("не удалось сгенерировать JWT refresh токен для пользователя %s", claims.Username))
		JsonError(w, "Произошла непредвиденная ошибка", http.StatusInternalServerError)
		return
	}

	_, err = a.Repo.Users.UpdateRefreshToken(claims.Username, newRefresh)
	if err != nil {
		a.Logger.WithErrorFields(r, err).Error(fmt.Sprintf("не удалось обновить JWT refresh в базе токен для пользователя %s", claims.Username))
		JsonError(w, "Произошла непредвиденная ошибка", http.StatusInternalServerError)
		return
	}

	msg := utils.JWTMessage(newJwt, newRefresh)
	utils.Respond(w, msg)
}
