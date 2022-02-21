package delivery

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/nedostupno/zinaida/internal/auth"
	"github.com/sirupsen/logrus"
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

type (
	responseData struct {
		status int
		size   int
	}

	loggingResponseWriter struct {
		http.ResponseWriter
		responseData *responseData
	}
)

func (r *loggingResponseWriter) Write(b []byte) (int, error) {
	size, err := r.ResponseWriter.Write(b)
	r.responseData.size += size
	return size, err
}

func (r *loggingResponseWriter) WriteHeader(statusCode int) {
	r.ResponseWriter.WriteHeader(statusCode)
	r.responseData.status = statusCode
}

func (a *Api) LoggingMidleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		responseData := &responseData{
			status: 0,
			size:   0,
		}
		lrw := loggingResponseWriter{
			ResponseWriter: w,
			responseData:   responseData,
		}

		h.ServeHTTP(&lrw, r)

		duration := time.Since(start)
		if responseData.status >= 400 {
			a.Logger.WithFields(logrus.Fields{
				"Success":  false,
				"URI":      r.RequestURI,
				"Method":   r.Method,
				"Status":   responseData.status,
				"Duration": duration,
				"Size":     responseData.size,
			}).Info()
			return
		}

		a.Logger.WithFields(logrus.Fields{
			"Success":  true,
			"URI":      r.RequestURI,
			"Method":   r.Method,
			"Status":   responseData.status,
			"Duration": duration,
			"Size":     responseData.size,
		}).Info()
	})
}