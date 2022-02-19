package auth

import (
	"time"

	"github.com/golang-jwt/jwt"
)

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
