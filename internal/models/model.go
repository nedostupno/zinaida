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

type NodeAgent struct {
	Id     int    `json:"id"`
	Ip     string `json:"ip"`
	Domain string `json:"domain"`
}

type CPU struct {
	Model   string
	Cpu_s   string
	Min_MHz string
	Max_MHz string
}

type TopProc struct {
	First  string
	Second string
	Third  string
	Fourth string
	Fifth  string
}
