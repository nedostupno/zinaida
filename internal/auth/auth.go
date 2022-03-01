package auth

import (
	"time"

	"github.com/golang-jwt/jwt"
)

type CustomClaims struct {
	Username string `json:"Username"`
	jwt.StandardClaims
}

func GenerateJWTToken(u string, key string, ttl int) (string, error) {

	claims := CustomClaims{
		Username: u,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Duration(ttl) * time.Minute).Unix(),
			IssuedAt:  time.Now().Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := token.SignedString([]byte(key))
	if err != nil {
		return "", err
	}
	return ss, nil
}

func GenerateRefreshToken(u string, key string, ttl int) (string, error) {
	claims := CustomClaims{
		Username: u,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Duration(ttl) * time.Minute).Unix(),
			IssuedAt:  time.Now().Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := token.SignedString([]byte(key))
	if err != nil {
		return "", err
	}
	return ss, nil
}
