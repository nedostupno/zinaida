package manager

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/nedostupno/zinaida/internal/auth"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func (s *Server) JwtAuthenticationInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	// Определяем эндпоинты, которые не требуют аутентификации
	notAuth := []string{"/protoManager.manager/Login", "/protoManager.manager/Refresh", "/protoManager.manager/Registrate"}
	requestPath := info.FullMethod

	for _, v := range notAuth {
		if v == requestPath {
			return handler(ctx, req)
		}
	}

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		s.logger.WhithErrorFields(fmt.Errorf("failed to get metadata from incomming context")).Error()
		return nil, status.Error(codes.Internal, "An unexpected error has occurred")
	}

	authHeader := md.Get("authorization")
	if len(authHeader) == 0 {
		return nil, status.Error(codes.Unauthenticated, "Missed auth token")
	}

	splittedHeader := strings.Split(authHeader[0], " ")
	if len(splittedHeader) != 2 || splittedHeader[0] != "Bearer" {
		return nil, status.Error(codes.Unauthenticated, "Invalid header auth")
	}

	tokenFromHeader := splittedHeader[1]

	token, err := jwt.ParseWithClaims(tokenFromHeader, &auth.CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.cfg.Jwt.SecretKeyForAccessToken), nil
	})

	if err != nil || !token.Valid {

		return nil, status.Error(codes.Unauthenticated, "Invalid authentication token")
	}

	return handler(ctx, req)
}

type (
	responseData struct {
		status int
		size   int
	}

	// Создаем собственный ReponseWriter, чтобы:
	// - сохранить имплементацию инфтерфейса http.Hijacker при проходе
	// через middleware
	// - получить информацию о статусе ответа и размере ответа
	loggingResponseWriter struct {
		http.ResponseWriter
		http.Hijacker
		responseData *responseData
	}
)

// Реализуем свой метод Write, чтобы получить информацию о размере ответа
func (r *loggingResponseWriter) Write(b []byte) (int, error) {
	size, err := r.ResponseWriter.Write(b)
	r.responseData.size += size
	return size, err
}

// Реализуем свой метод WriteHeader, чтобы получить статуст ответа
func (r *loggingResponseWriter) WriteHeader(statusCode int) {
	r.ResponseWriter.WriteHeader(statusCode)
	r.responseData.status = statusCode
}

func (a *Server) LoggingMidleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		responseData := &responseData{
			status: 0,
			size:   0,
		}

		hij, ok := w.(http.Hijacker)
		if !ok {
			a.logger.WhithErrorFields(fmt.Errorf("websocket: responseWriter does not implement http.Hijacker")).Fatal()
		}

		lrw := loggingResponseWriter{
			ResponseWriter: w,
			Hijacker:       hij,
			responseData:   responseData,
		}

		h.ServeHTTP(&lrw, r)

		duration := time.Since(start)
		if responseData.status >= 400 {
			a.logger.WithFields(logrus.Fields{
				"Success":  false,
				"URI":      r.RequestURI,
				"Method":   r.Method,
				"Status":   responseData.status,
				"Duration": duration,
				"Size":     responseData.size,
				"address":  r.RemoteAddr,
			}).Info()
			return
		}

		a.logger.WithFields(logrus.Fields{
			"Success":  true,
			"URI":      r.RequestURI,
			"Method":   r.Method,
			"Status":   responseData.status,
			"Duration": duration,
			"Size":     responseData.size,
			"address":  r.RemoteAddr,
		}).Info()
	})
}

func (s Server) httpResponseModifier(ctx context.Context, w http.ResponseWriter, p proto.Message) error {
	md, ok := runtime.ServerMetadataFromContext(ctx)
	if !ok {
		log.Fatal("\nSYKA")
	}

	// set http status code
	if vals := md.HeaderMD.Get("x-http-code"); len(vals) > 0 {
		code, err := strconv.Atoi(vals[0])
		if err != nil {
			return err
		}
		// delete the headers to not expose any grpc-metadata in http response
		delete(md.HeaderMD, "x-http-code")
		delete(w.Header(), "Grpc-Metadata-X-Http-Code")
		w.WriteHeader(code)
	}

	return nil
}

func (s *Server) StreamServerJWTInterceptor(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	ctx := ss.Context()
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		s.logger.WhithErrorFields(fmt.Errorf("failed to get metadata from incomming context")).Error()
		return status.Error(codes.Internal, "An unexpected error has occurred")
	}

	authHeader := md.Get("authorization")
	if len(authHeader) == 0 {
		return status.Error(codes.Unauthenticated, "Missed auth token")
	}
	splittedHeader := strings.Split(authHeader[0], " ")
	if len(splittedHeader) != 2 || splittedHeader[0] != "Bearer" {
		return status.Error(codes.Unauthenticated, "Invalid header auth")
	}

	tokenFromHeader := splittedHeader[1]

	token, err := jwt.ParseWithClaims(tokenFromHeader, &auth.CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.cfg.Jwt.SecretKeyForAccessToken), nil
	})

	if err != nil || !token.Valid {

		return status.Error(codes.Unauthenticated, "Invalid authentication token")
	}

	return handler(srv, ss)
}

type APIError struct {
	Msg  string `json:"message"`
	Code string `json:"code"`
}

func (a APIError) Error() string {
	return a.Msg
}

func (s *Server) CustomHTTPError(ctx context.Context, mux *runtime.ServeMux, marshaler runtime.Marshaler, w http.ResponseWriter, r *http.Request, err error) {
	w.Header().Set("Content-type", "application/json")
	w.WriteHeader(runtime.HTTPStatusFromCode(status.Code(err)))

	code := status.Code(err).String()
	fmt.Printf("err: %v\n", err)
	err = APIError{
		Msg:  status.Convert(err).Message(),
		Code: code,
	}

	isContain := strings.Contains(err.Error(), "unknown field")
	if isContain {
		err = APIError{
			Msg:  "Request body contains unknown json fields",
			Code: code,
		}
	}
	json.NewEncoder(w).Encode(err)

}
