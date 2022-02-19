package auth

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/nedostupno/zinaida/internal/auth/utils"

	"github.com/nedostupno/zinaida/internal/models"
)

var JwtAuthentication = func(next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		notAuth := []string{"/api/login/"} //Список эндпоинтов, для которых не требуется авторизация
		requestPath := r.URL.Path          //текущий путь запроса

		//проверяем, не требует ли запрос аутентификации, обслуживаем запрос, если он не нужен
		for _, value := range notAuth {

			if value == requestPath {
				next.ServeHTTP(w, r)
				return
			}
		}

		response := make(map[string]interface{})
		tokenHeader := r.Header.Get("Authorization") //Получение токена

		if tokenHeader == "" { //Токен отсутствует, возвращаем  403 http-код Unauthorized
			response = utils.Message(false, "Missing auth token")
			w.WriteHeader(http.StatusForbidden)
			w.Header().Add("Content-Type", "application/json")
			utils.Respond(w, response)
			return
		}

		splitted := strings.Split(tokenHeader, " ") //Токен обычно поставляется в формате `Bearer {token-body}`, мы проверяем, соответствует ли полученный токен этому требованию
		if len(splitted) != 2 {
			response = utils.Message(false, "Invalid/Malformed auth token")
			w.WriteHeader(http.StatusForbidden)
			w.Header().Add("Content-Type", "application/json")
			utils.Respond(w, response)
			return
		}

		tokenPart := splitted[1] //Получаем вторую часть токена
		tk := &models.Token{}

		token, err := jwt.ParseWithClaims(tokenPart, tk, func(token *jwt.Token) (interface{}, error) {
			return []byte("shaka-waka"), nil
		})

		if err != nil { //Неправильный токен, как правило, возвращает 403 http-код
			response = utils.Message(false, "Malformed authentication token")
			w.WriteHeader(http.StatusForbidden)
			w.Header().Add("Content-Type", "application/json")
			utils.Respond(w, response)
			return
		}

		if !token.Valid { //токен недействителен, возможно, не подписан на этом сервере
			response = utils.Message(false, "Token is not valid.")
			w.WriteHeader(http.StatusForbidden)
			w.Header().Add("Content-Type", "application/json")
			utils.Respond(w, response)
			return
		}

		//Всё прошло хорошо, продолжаем выполнение запроса
		ctx := context.WithValue(r.Context(), "user", tk.UserId)
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r) //передать управление следующему обработчику!
	})
}

type CustomClaims struct {
	Username string `json:"Username"`
	jwt.StandardClaims
}

func GenerateJWTToken(u string) (string, error) {
	signingKey := []byte("shaka-waka")

	claims := CustomClaims{
		Username: u,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(3 * time.Minute).Unix(),
			IssuedAt:  time.Now().Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := token.SignedString(signingKey)
	if err != nil {
		return "", err
	}
	return ss, nil
}

func GenerateRefreshToken(u string) (string, error) {
	signingKey := []byte("Baka-sraka")

	claims := CustomClaims{
		Username: u,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(2 * time.Minute).Unix(),
			IssuedAt:  time.Now().Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := token.SignedString(signingKey)
	if err != nil {
		return "", err
	}
	return ss, nil
}
