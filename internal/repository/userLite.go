package repository

import (
	"database/sql"

	_ "github.com/mattn/go-sqlite3"
)

type UsersLite struct {
	db *sql.DB
}

func NewUsersLite(db *sql.DB) *UsersLite {
	return &UsersLite{db: db}
}
