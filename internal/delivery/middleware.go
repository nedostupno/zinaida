package delivery

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt"
	"github.com/nedostupno/zinaida/internal/auth"
)

func (a *Api) JwtAuthenticationMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		notAuth := []string{"/api/login/", "/api/refresh/"}
		requestPath := r.URL.Path

		for _, value := range notAuth {
			if value == requestPath {
				h.ServeHTTP(w, r)
				return
			}
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			w.Write([]byte(fmt.Sprintf("Не предоставлен токен аутентификатции")))
			return
		}

		splittedHeader := strings.Split(authHeader, " ")
		if len(splittedHeader) != 2 || splittedHeader[0] != "Bearer" {
			w.Write([]byte(fmt.Sprintf("Некорректный токен аутентификации")))
			return
		}

		tokenFromHeader := splittedHeader[1]

		token, err := jwt.ParseWithClaims(tokenFromHeader, &auth.CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte("shaka-waka"), nil
		})

		if err != nil || !token.Valid {
			w.Write([]byte(fmt.Sprintf("Некорректный токен аутентификации")))
			return
		}

		h.ServeHTTP(w, r)
	})
}
