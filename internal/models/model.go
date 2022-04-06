package models

type NodeAgent struct {
	Id          int    `json:"id"`
	Ip          string `json:"ip"`
	Domain      string `json:"domain"`
	Unreachable int    `json:"unreachable"`
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
