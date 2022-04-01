package rest

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"

	"github.com/golang-jwt/jwt"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/nedostupno/zinaida/internal/auth"
	models "github.com/nedostupno/zinaida/internal/models"
	"github.com/nedostupno/zinaida/traceroute"
)

func Respond(w http.ResponseWriter, data map[string]interface{}, code int) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(data)
}

type APIError struct {
	Success bool   `json:"success"`
	Msg     string `json:"error"`
}

func JsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	err := APIError{
		Success: false,
		Msg:     msg,
	}
	json.NewEncoder(w).Encode(err)
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

func (a *api) GetMap(w http.ResponseWriter, r *http.Request) {
	destinations := []string{}

	nodes, err := a.repo.ListAllNodes()
	if len(nodes) == 0 {
		msg := map[string]interface{}{
			"success": true,
			"message": "There are no agent nodes in monitoring. Unable to build network map",
		}
		Respond(w, msg, http.StatusOK)
	}

	for _, node := range nodes {
		if node.Domain != "" {
			destinations = append(destinations, node.Domain)
		} else {
			destinations = append(destinations, node.Ip)
		}
	}
	if err != nil {
		a.logger.WithRestApiErrorFields(r, err).Error("Failed to get a list of all monitored nodes from the database ")
		JsonError(w, "An unexpected error has occurred", http.StatusInternalServerError)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		JsonError(w, "failed to upgrade connection", http.StatusInternalServerError)
		return
	}
	defer conn.Close()

	hops := make(chan traceroute.Hop, 15)
	result := make(chan models.TraceResult)
	go func() {
		defer close(hops)
		for i, domain := range destinations {
			t := traceroute.NewTracer(a.cfg)
			err := t.Traceroute(i, domain, hops, result)
			if err != nil {
				a.logger.WithRestApiErrorFields(r, err).Errorf("Failed to build trace to node %v", domain)
				JsonError(w, "An unexpected error has occurred", http.StatusInternalServerError)
				return
			}
		}
	}()

	go func() {
		for res := range result {

			node, err := a.repo.Nodes.GetNodeByIP(string(res.Addr))
			if err != nil {
				a.logger.WithRestApiErrorFields(r, err).Errorf("Failed to get node with ip %v from database", res.Addr)
				JsonError(w, "An unexpected error has occurred", http.StatusInternalServerError)
				return
			}

			cnt, err := a.repo.Nodes.GetNodeUnreachableCounter(node.Id)
			if err != nil {
				a.logger.WithRestApiErrorFields(r, err).Errorf("Failed to get the value of the Unreachable field from the database for the node with id %v", node.Id)
				JsonError(w, "An unexpected error has occurred", http.StatusInternalServerError)
				return
			}

			if res.Unreachable {
				_, err := a.repo.Nodes.UpdateNodeUnreachableCounter(node.Id, cnt+1)
				if err != nil {
					a.logger.WithRestApiErrorFields(r, err).Errorf("Failed to change the value of the Unreachable field in the database for the node with id %v", node.Id)
					JsonError(w, "An unexpected error has occurred", http.StatusInternalServerError)
					return
				}
			} else {
				_, err := a.repo.Nodes.UpdateNodeUnreachableCounter(node.Id, 0)
				if err != nil {
					a.logger.WithRestApiErrorFields(r, err).Errorf("Failed to change the value of the Unreachable field in the database for the node with id %v", node.Id)
					JsonError(w, "An unexpected error has occurred", http.StatusInternalServerError)
					return
				}
			}
		}
	}()

	for hop := range hops {
		if err := conn.WriteJSON(hop); err != nil {
			a.logger.WithRestApiErrorFields(r, err).Errorf("Failed to marshal to json and send hop to client: %v", hop)
			JsonError(w, "An unexpected error has occurred", http.StatusInternalServerError)
			return
		}
	}
}

func (a *api) GetNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := a.repo.ListAllNodes()
	if err != nil {
		a.logger.WithRestApiErrorFields(r, err).Error("Failed to get a list of all monitored nodes from the database ")
		JsonError(w, "An unexpected error has occurred", http.StatusInternalServerError)
		return
	}

	msg := map[string]interface{}{
		"success": true,
		"message": "List of nodes received",
		"node":    nodes,
	}
	Respond(w, msg, http.StatusOK)
}

func (a *api) CreateNode(w http.ResponseWriter, r *http.Request) {
	var n models.NodeAgent
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&n); err != nil {
		a.logger.WithRestApiErrorFields(r, err).Error("failed to decode structure r.Body")
		JsonError(w, "Failed to process submitted data", http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	if n.Domain == "" && n.Ip == "" {
		JsonError(w, "Neither domain nor ip address was sent", http.StatusBadRequest)
		return
	}

	if n.Domain != "" {
		reg, err := regexp.Compile(`^([A-Za-zА-Яа-я0-9-]{1,63}\.)+[A-Za-zА-Яа-я0-9]{2,6}$`)
		if err != nil {
			a.logger.WithRestApiErrorFields(r, err).Error("failed to compile pattern for regular expression ")
			JsonError(w, "An unexpected error has occurred", http.StatusInternalServerError)
			return
		}
		okk := reg.MatchString(n.Domain)
		if !okk {
			JsonError(w, "Specified domain is not valid", http.StatusBadRequest)
			return
		}
		len := utf8.RuneCountInString(n.Domain)
		if len > 253 {
			JsonError(w, "Specified domain is too long", http.StatusBadRequest)
			return
		}
		resolvedIPs, err := net.LookupHost(n.Domain)
		if err != nil {
			if r, ok := err.(*net.DNSError); ok && r.IsNotFound {
				JsonError(w, fmt.Sprintf("Failed to get domain information %s", n.Domain), http.StatusOK)
				return
			}
			a.logger.WithRestApiErrorFields(r, err).Errorf("Unable to find ip for domain: %s", n.Domain)
			JsonError(w, "An unexpected error has occurred", http.StatusInternalServerError)
			return
		}

		if n.Ip == "" {
			n.Ip = resolvedIPs[0]
		}

		var ok bool
		for _, ip := range resolvedIPs {
			if ip == n.Ip {
				ok = true
			}
		}

		if !ok && n.Ip != "" {
			JsonError(w, "Specified ip address and ip address from domain resource records are different", http.StatusBadRequest)
			return
		}
	}

	if r := net.ParseIP(n.Ip); r == nil {
		JsonError(w, "Specified ip address is not valid ", http.StatusBadRequest)
		return
	}

	_, err := a.grpc.Ping(n.Ip, a.cfg.Grpc.AgentsPort, a.cfg.Grpc.PingTimeout)
	if err != nil {
		msg := map[string]interface{}{
			"success": false,
			"message": "Failed to connect to agent node",
			"node":    n,
		}
		Respond(w, msg, http.StatusOK)
		return
	}

	isExistByDomain, err := a.repo.Nodes.CheckNodeExistenceByDomain(n.Domain)
	if err != nil {
		a.logger.WithRestApiErrorFields(r, err).Errorf("failed to add node %v to monitoring", n)
		JsonError(w, "An unexpected error has occurred", http.StatusInternalServerError)
		return
	}
	isExistByIP, err := a.repo.Nodes.CheckNodeExistenceByIP(n.Ip)
	if err != nil {
		a.logger.WithRestApiErrorFields(r, err).Errorf("failed to add node %v to monitoring", n)
		JsonError(w, "An unexpected error has occurred", http.StatusInternalServerError)
		return
	}

	existNode, err := a.repo.GetNodeByIP(n.Ip)
	if err != nil {
		a.logger.WithRestApiErrorFields(r, err).Errorf("failed to get node with ip %s from database ", n.Ip)
		JsonError(w, "An unexpected error has occurred", http.StatusInternalServerError)
		return
	}

	if (isExistByDomain && n.Domain != "") || isExistByIP {
		msg := map[string]interface{}{
			"success": true,
			"message": "Node agent is already exist in monitoring",
			"node":    existNode,
		}
		Respond(w, msg, http.StatusOK)
		return
	}

	_, err = a.repo.AddNode(n.Ip, n.Domain)
	if err != nil {
		a.logger.WithRestApiErrorFields(r, err).Errorf("failed to add node %v to monitoring", n)
		JsonError(w, "An unexpected error has occurred", http.StatusInternalServerError)
		return
	}

	node, err := a.repo.GetNodeByIP(n.Ip)
	if err != nil {
		a.logger.WithRestApiErrorFields(r, err).Errorf("failed to get node with ip %s from database ", n.Ip)
		JsonError(w, "An unexpected error has occurred", http.StatusInternalServerError)
		return
	}

	msg := map[string]interface{}{
		"success": true,
		"message": "Agent node successfully registered",
		"node":    node,
	}
	Respond(w, msg, http.StatusCreated)
}

func (a *api) GetNodeInfo(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		JsonError(w, fmt.Sprintf("Agent nodes with id %d were not found in monitoring", id), http.StatusNotFound)
		return
	}

	isExist, err := a.repo.Nodes.CheckNodeExistenceByID(id)
	if err != nil {
		a.logger.WithRestApiErrorFields(r, err).Errorf("failed to check if node with id %s exists in the database", id)
		JsonError(w, "An unexpected error has occurred", http.StatusInternalServerError)
		return
	}

	if !isExist {
		JsonError(w, fmt.Sprintf("Agent nodes with id %d were not found in monitoring", id), http.StatusNotFound)
		return
	}

	node, err := a.repo.GetNodeByID(id)
	if err != nil {
		a.logger.WithRestApiErrorFields(r, err).Errorf("failed to get node with id %s from database", id)
		JsonError(w, "An unexpected error has occurred", http.StatusInternalServerError)
		return
	}

	msg := map[string]interface{}{
		"success": true,
		"message": "Information about the node-agent was successfully received",
		"node":    node,
	}
	Respond(w, msg, http.StatusOK)
}

func (a *api) DeleteNode(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		JsonError(w, fmt.Sprintf("Agent nodes with id %d were not found in monitoring", id), http.StatusNotFound)
		return
	}

	isExist, err := a.repo.Nodes.CheckNodeExistenceByID(id)
	if err != nil {
		a.logger.WithRestApiErrorFields(r, err).Errorf("не удалось проверить наличие ноды с id %s в базе данных", id)
		JsonError(w, "An unexpected error has occurred", http.StatusInternalServerError)
		return
	}

	if !isExist {
		JsonError(w, fmt.Sprintf("Agent nodes with id %d were not found in monitoring", id), http.StatusNotFound)
		return
	}

	_, err = a.repo.DeleteNode(id)
	if err != nil {
		a.logger.WithRestApiErrorFields(r, err).Errorf("failed to remove node with id %s from the database", id)
		JsonError(w, "An unexpected error has occurred", http.StatusInternalServerError)
		return
	}

	msg := map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("Agent node with id %d was successfully removed from monitoring ", id),
	}
	Respond(w, msg, http.StatusOK)
}

func (a *api) GetStat(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		JsonError(w, fmt.Sprintf("Agent nodes with id %d were not found in monitoring", id), http.StatusNotFound)
		return
	}

	isExist, err := a.repo.Nodes.CheckNodeExistenceByID(id)
	if err != nil {
		a.logger.WithRestApiErrorFields(r, err).Errorf("failed to check if node with id %s exists in the database ", id)
		JsonError(w, "An unexpected error has occurred", http.StatusInternalServerError)
		return
	}

	if !isExist {
		JsonError(w, fmt.Sprintf("Agent nodes with id %d were not found in monitoring", id), http.StatusNotFound)
		return
	}

	node, err := a.repo.GetNodeByID(id)
	if err != nil {
		a.logger.WithRestApiErrorFields(r, err).Errorf("failed to get node with id %s from database ", id)
		JsonError(w, "An unexpected error has occurred", http.StatusInternalServerError)
		return
	}
	_, err = a.grpc.Ping(node.Ip, a.cfg.Grpc.AgentsPort, a.cfg.Grpc.PingTimeout)
	if err != nil {

		msg := map[string]interface{}{
			"success": false,
			"message": fmt.Sprintf("Failed to connect to agent node with id  %d", node.Id),
			"node":    node,
			"stat":    nil,
		}
		Respond(w, msg, http.StatusOK)
		return
	}

	resp, err := a.grpc.GetStat(node.Ip, a.cfg.Grpc.AgentsPort)
	if err != nil {
		a.logger.WithRestApiErrorFields(r, err).Errorf("failed to get grpc stats about node  %v", node)
		JsonError(w, "An unexpected error has occurred", http.StatusInternalServerError)
		return
	}

	msg := map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("Statistics collected from agent node with id %d", node.Id),
		"node":    node,
		"stat":    resp,
	}
	Respond(w, msg, http.StatusOK)
}

func (a *api) RebootNode(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		JsonError(w, fmt.Sprintf("Agent nodes with id %d were not found in monitoring", id), http.StatusNotFound)
		return
	}

	isExist, err := a.repo.Nodes.CheckNodeExistenceByID(id)
	if err != nil {
		a.logger.WithRestApiErrorFields(r, err).Errorf("failed to check if node with id %s exists in the database", id)
		JsonError(w, "An unexpected error has occurred", http.StatusInternalServerError)
		return
	}

	if !isExist {
		JsonError(w, fmt.Sprintf("Agent nodes with id %d were not found in monitoring", id), http.StatusNotFound)
		return
	}

	node, err := a.repo.GetNodeByID(id)
	if err != nil {
		a.logger.WithRestApiErrorFields(r, err).Errorf("failed to get node with id %s from database", id)
		JsonError(w, "An unexpected error has occurred", http.StatusInternalServerError)
		return
	}
	_, err = a.grpc.Ping(node.Ip, a.cfg.Grpc.AgentsPort, a.cfg.Grpc.PingTimeout)
	if err != nil {

		msg := map[string]interface{}{
			"success": false,
			"message": fmt.Sprintf("Failed to connect to agent node with id %d", node.Id),
			"node":    node,
			"stat":    nil,
		}
		Respond(w, msg, http.StatusOK)
		return
	}

	_, err = a.grpc.RebootNode(node.Ip, a.cfg.Grpc.AgentsPort)
	if err != nil {
		a.logger.WithRestApiErrorFields(r, err).Errorf("не удалось выполнить перезагрузку ноды-агента с id %s", id)
		msg := map[string]interface{}{
			"success": false,
			"message": fmt.Sprintf("Не удалось выполнить перезагрузку ноды-агента с id %d", node.Id),
			"node":    node,
		}
		Respond(w, msg, http.StatusOK)
		return
	}

	msg := map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("Нода-агент с id %d будет перезагружена через 1 минуту", node.Id),
		"node":    node,
	}
	Respond(w, msg, http.StatusOK)
}

func (a *api) Login(w http.ResponseWriter, r *http.Request) {

	var creds models.Credential

	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		a.logger.WithRestApiErrorFields(r, err).Error("failed to decode structure r.Body ")
		JsonError(w, "Failed to process submitted data", http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	exist, err := a.repo.Users.IsExist(creds.Username)
	if err != nil {
		a.logger.WithRestApiErrorFields(r, err).Errorf("failed to check the existence of user %s in the database", creds.Username)
		JsonError(w, "An unexpected error has occurred", http.StatusInternalServerError)
		return
	}

	if !exist {
		JsonError(w, "Incorrect data sent", http.StatusUnauthorized)
		return
	}

	user, err := a.repo.Users.Get(creds.Username)
	if err != nil {
		a.logger.WithRestApiErrorFields(r, err).Errorf("failed to get user %s from database", creds.Username)
		JsonError(w, "An unexpected error has occurred", http.StatusInternalServerError)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(creds.Password))
	if creds.Username == user.Username && err == nil {
		jwt, err := auth.GenerateJWTToken(user.Username, a.cfg.Jwt.SecretKeyForAccessToken, a.cfg.Jwt.AccessTokenTTL)
		if err != nil {
			a.logger.WithRestApiErrorFields(r, err).Errorf("failed to generate JWT access token for user %s", user.Username)
			JsonError(w, "An unexpected error has occurred", http.StatusInternalServerError)
			return
		}

		refresh, err := auth.GenerateRefreshToken(user.Username, a.cfg.Jwt.SecretKeyForRefreshToken, a.cfg.Jwt.RefreshTokenTTL)
		if err != nil {
			a.logger.WithRestApiErrorFields(r, err).Errorf("failed to generate JWT refresh token for user %s ", user.Username)
			JsonError(w, "An unexpected error has occurred", http.StatusInternalServerError)
			return
		}

		_, err = a.repo.Users.UpdateRefreshToken(user.Username, refresh)
		if err != nil {
			a.logger.WithRestApiErrorFields(r, err).Errorf("failed to update JWT refresh token in database for user %s ", user.Username)
			JsonError(w, "An unexpected error has occurred", http.StatusInternalServerError)
			return
		}

		msg := map[string]interface{}{
			"success":       true,
			"access_token":  jwt,
			"refresh_token": refresh,
		}
		Respond(w, msg, http.StatusOK)
		return
	}
	JsonError(w, "Incorrect data sent", http.StatusUnauthorized)
}

func (a *api) Refresh(w http.ResponseWriter, r *http.Request) {

	var refresh models.RefreshToken
	err := json.NewDecoder(r.Body).Decode(&refresh)
	if err != nil {
		a.logger.WithRestApiErrorFields(r, err).Error("failed to decode structure r.Body ")
		JsonError(w, "Failed to process submitted data", http.StatusInternalServerError)
		return
	}

	if refresh.Token == "" {
		JsonError(w, "Missed refresh token", http.StatusUnauthorized)
		return
	}

	claims := &auth.CustomClaims{}

	token, err := jwt.ParseWithClaims(refresh.Token, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(a.cfg.Jwt.SecretKeyForRefreshToken), nil
	})

	// Ошибка будет выброшена даже в том случае, если токен истек, так что ручные проверки не требуются
	if err != nil || !token.Valid {
		JsonError(w, "invalid refresh token", http.StatusUnauthorized)
		return
	}

	exist, err := a.repo.Users.IsExist(claims.Username)
	if err != nil {
		a.logger.WithRestApiErrorFields(r, err).Errorf("failed to check the existence of user %s in the database", claims.Username)
		JsonError(w, "An unexpected error has occurred", http.StatusInternalServerError)
		return
	}

	if !exist {
		JsonError(w, "invalid refresh token", http.StatusUnauthorized)
		return
	}

	oldRefreshToken, err := a.repo.Users.GetRefreshToken(claims.Username)
	if err != nil {
		a.logger.WithRestApiErrorFields(r, err).Errorf("failed to get refresh token for user %s from database", claims.Username)
		JsonError(w, "An unexpected error has occurred", http.StatusInternalServerError)
		return
	}

	if refresh.Token != oldRefreshToken {
		JsonError(w, "invalid refrsh token", http.StatusUnauthorized)
		return
	}

	newJwt, err := auth.GenerateJWTToken(claims.Username, a.cfg.Jwt.SecretKeyForAccessToken, a.cfg.Jwt.AccessTokenTTL)
	if err != nil {
		a.logger.WithRestApiErrorFields(r, err).Errorf("failed to generate JWT access token for user %s ", claims.Username)
		JsonError(w, "An unexpected error has occurred", http.StatusInternalServerError)
		return
	}

	newRefresh, err := auth.GenerateRefreshToken(claims.Username, a.cfg.Jwt.SecretKeyForRefreshToken, a.cfg.Jwt.RefreshTokenTTL)
	if err != nil {
		a.logger.WithRestApiErrorFields(r, err).Errorf("failed to generate JWT refresh token for user %s", claims.Username)
		JsonError(w, "An unexpected error has occurred", http.StatusInternalServerError)
		return
	}

	_, err = a.repo.Users.UpdateRefreshToken(claims.Username, newRefresh)
	if err != nil {
		a.logger.WithRestApiErrorFields(r, err).Errorf("failed to update JWT refresh in token database for user %s", claims.Username)
		JsonError(w, "An unexpected error has occurred", http.StatusInternalServerError)
		return
	}

	msg := map[string]interface{}{
		"success":       true,
		"access_token":  newJwt,
		"refresh_token": newRefresh,
	}
	Respond(w, msg, http.StatusOK)
}
