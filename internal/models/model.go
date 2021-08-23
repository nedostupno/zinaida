package models

import "github.com/dgrijalva/jwt-go"

type Token struct {
	UserId uint
	jwt.StandardClaims
}

type Account struct {
	Password string `json:"password"`
	Login    string `json:"login"`
}

type Credential struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
