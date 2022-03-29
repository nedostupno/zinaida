package repository

import (
	"database/sql"

	"github.com/nedostupno/zinaida/internal/models"
)

type Users interface {
	IsExist(username string) (bool, error)
	Get(username string) (models.User, error)
	GetRefreshToken(username string) (string, error)
	UpdateRefreshToken(username string, token string) (sql.Result, error)
}

type Nodes interface {
	AddNode(ip string, domain string) (sql.Result, error)
	ListAllNodes() ([]models.NodeAgent, error)
	GetNodeByIP(ip string) (models.NodeAgent, error)
	GetNodeByID(id string) (models.NodeAgent, error)
	DeleteNode(id string) (sql.Result, error)
	CheckNodeExistenceByIP(ip string) (bool, error)
	CheckNodeExistenceByID(id string) (bool, error)
	CheckNodeExistenceByDomain(domain string) (bool, error)
	GetAllNodesIP() ([]string, error)
	GetNodeUnreachableCounter(id int) (int, error)
	UpdateNodeUnreachableCounter(id int, value int) (sql.Result, error)
}

type Repository struct {
	Users
	Nodes
}

func NewRepository(db *sql.DB) *Repository {
	return &Repository{
		Users: NewUsersLite(db),
		Nodes: NewNodesLite(db),
	}
}
