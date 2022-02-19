package repository

import (
	"database/sql"

	_ "github.com/mattn/go-sqlite3"
	"github.com/nedostupno/zinaida/internal/models"
)

type UsersLite struct {
	db *sql.DB
}

func NewUsersLite(db *sql.DB) *UsersLite {
	return &UsersLite{db: db}
}

func (u *UsersLite) IfExist(username string) (bool, error) {
	var isExist bool
	err := u.db.QueryRow("SELECT exists (SELECT 1 FROM Users WHERE username == $1)", username).Scan(&isExist)
	if err != nil {
		return false, err
	}

	return isExist, nil
}

func (u *UsersLite) Get(username string) (models.User, error) {
	row := u.db.QueryRow("SELECT * FROM Users WHERE username = $1", username)
	user := models.User{}
	err := row.Scan(&user.Id, &user.Username, &user.Password, &user.Refresh_token)
	if err != nil {
		return models.User{}, err
	}
	return user, nil
}

func (u *UsersLite) GetRefreshToken(username string) (string, error) {
	row := u.db.QueryRow("SELECT refresh_token FROM Users WHERE username = $1", username)
	var token string
	err := row.Scan(&token)
	if err != nil {
		return "", err
	}
	return token, nil
}

func (u *UsersLite) UpdateRefreshToken(username string, token string) (sql.Result, error) {
	return u.db.Exec("UPDATE Users SET refresh_token = $1 WHERE username = $2", token, username)
}
