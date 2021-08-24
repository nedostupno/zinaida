package repository

import (
	"database/sql"

	_ "github.com/mattn/go-sqlite3"
	"github.com/nedostupno/zinaida/internal/models"
)

type NodesLite struct {
	db *sql.DB
}

func NewNodesLite(db *sql.DB) *NodesLite {
	return &NodesLite{db: db}
}

func (n *NodesLite) AddNode(ip string, domain string) (sql.Result, error) {
	result, err := n.db.Exec("insert into Nodes (ip, domain) values ($1, $2)",
		ip, domain)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (n *NodesLite) ListAllNodes() ([]models.NodeAgent, error) {
	rows, err := n.db.Query("SELECT * FROM Nodes")
	if err != nil {
		return nil, err
	}
	allNodes := []models.NodeAgent{}
	for rows.Next() {
		a := models.NodeAgent{}
		err := rows.Scan(&a.Id, &a.Ip, &a.Domain)
		if err != nil {
			return nil, err
		}
		allNodes = append(allNodes, a)
	}
	return allNodes, nil
}

func (n *NodesLite) GetNode(ip string) (models.NodeAgent, error) {
	row := n.db.QueryRow("SELECT * FROM Nodes WHERE ip = $1", ip)
	node := models.NodeAgent{}
	err := row.Scan(&node.Id, &node.Ip, &node.Domain)
	if err != nil {
		return models.NodeAgent{}, err
	}
	return node, nil
}
