package repository

import (
	"database/sql"

	_ "github.com/mattn/go-sqlite3"
)

func NewSqliteDB() (*sql.DB, error) {
	db, err := sql.Open("sqlite3", "zinaida.db")
	if err != nil {
		return nil, err
	}

	db.Exec(`CREATE TABLE if not exists Users (
		id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE, 
		username TEXT,
		password TEXT
	  )`)
	db.Exec(`CREATE TABLE if not exists Nodes (
		id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE, 
		ip TEXT,
		domain TEXT
	  )`)

	return db, nil
}
