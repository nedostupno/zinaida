package repository

import (
	"database/sql"

	"github.com/nedostupno/zinaida/internal/models"
)

type User interface {
}

type Nodes interface {
	AddNode(ip string, domain string) (sql.Result, error)
	ListAllNodes() ([]models.NodeAgent, error)
}

type Repository struct {
	User
	Nodes
}

func NewRepository(db *sql.DB) *Repository {
	return &Repository{
		User:  NewUsersLite(db),
		Nodes: NewNodesLite(db),
	}
}
