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
	result, err := n.db.Exec("insert into Nodes (ip, domain, unreachable) values ($1, $2, 0)",
		ip, domain)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (n *NodesLite) DeleteNode(id string) (sql.Result, error) {
	result, err := n.db.Exec("DELETE FROM Nodes WHERE id = $1", id)
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
		err := rows.Scan(&a.Id, &a.Ip, &a.Domain, &a.Unreachable)
		if err != nil {
			return nil, err
		}
		allNodes = append(allNodes, a)
	}
	return allNodes, nil
}

func (n *NodesLite) GetNodeByIP(ip string) (models.NodeAgent, error) {
	row := n.db.QueryRow("SELECT * FROM Nodes WHERE ip = $1", ip)
	node := models.NodeAgent{}
	err := row.Scan(&node.Id, &node.Ip, &node.Domain, &node.Unreachable)
	if err != nil {
		return models.NodeAgent{}, err
	}
	return node, nil
}

func (n *NodesLite) GetNodeByID(id string) (models.NodeAgent, error) {
	row := n.db.QueryRow("SELECT * FROM Nodes WHERE id = $1", id)
	node := models.NodeAgent{}
	err := row.Scan(&node.Id, &node.Ip, &node.Domain, &node.Unreachable)
	if err != nil {
		return models.NodeAgent{}, err
	}
	return node, nil
}

func (n *NodesLite) CheckNodeExistenceByIP(ip string) (bool, error) {
	var isExist bool
	err := n.db.QueryRow("SELECT exists (SELECT 1 FROM Nodes WHERE ip == $1)", ip).Scan(&isExist)
	if err != nil {
		return false, err
	}

	return isExist, nil
}

func (n *NodesLite) CheckNodeExistenceByID(id string) (bool, error) {
	var isExist bool
	err := n.db.QueryRow("SELECT exists (SELECT 1 FROM Nodes WHERE id == $1)", id).Scan(&isExist)
	if err != nil {
		return false, err
	}
	return isExist, nil
}

func (n *NodesLite) CheckNodeExistenceByDomain(domain string) (bool, error) {
	var isExist bool
	err := n.db.QueryRow("SELECT exists (SELECT 1 FROM Nodes WHERE domain == $1)", domain).Scan(&isExist)
	if err != nil {
		return false, err
	}
	return isExist, nil
}

func (n *NodesLite) GetAllNodesIP() ([]string, error) {
	rows, err := n.db.Query("SELECT ip FROM Nodes")
	if err != nil {
		return nil, err
	}

	var ips []string

	for rows.Next() {
		var ip string
		err := rows.Scan(&ip)
		if err != nil {
			return nil, err
		}
		ips = append(ips, ip)
	}
	return ips, nil
}
