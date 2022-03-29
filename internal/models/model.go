package models

import "github.com/golang-jwt/jwt"

type Token struct {
	UserId uint
	jwt.StandardClaims
}

type RefreshToken struct {
	Token string `json:"token"`
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
	Id          int    `json:"id"`
	Ip          string `json:"ip"`
	Domain      string `json:"domain"`
	Unreachable int    `json:"unreachable"`
}

type CPU struct {
	Model   string `json:"model,omitempty"`
	Cpu_s   string `json:"cpu___s,omitempty"`
	Min_MHz string `json:"min___m_hz,omitempty"`
	Max_MHz string `json:"max___m_hz,omitempty"`
}

type TopProc struct {
	First  string `json:"first,omitempty"`
	Second string `json:"second,omitempty"`
	Third  string `json:"third,omitempty"`
	Fourth string `json:"fourth,omitempty"`
	Fifth  string `json:"fifth,omitempty"`
}

type User struct {
	Id            int
	Username      string
	Password      string
	Refresh_token string
}

type TraceResult struct {
	Addr        string
	Unreachable bool
}
