package manager

import (
	"context"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt"
	"github.com/nedostupno/zinaida/internal/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func (s *Server) JwtAuthenticationInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	// Определяем эндпоинты, которые не требуют аутентификации
	notAuth := []string{"/protoManager.manager/login/", "/protoManager.manager/refresh/"}
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
		r := status.New(codes.Unauthenticated, "Invalid authentication token")
		return nil, r.Err()
	}

	return handler(ctx, req)
}
