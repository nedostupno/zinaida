package delivery

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/nedostupno/zinaida/internal/auth"
	"github.com/nedostupno/zinaida/internal/auth/utils"
	models "github.com/nedostupno/zinaida/internal/models"
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
