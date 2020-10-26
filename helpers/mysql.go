package helpers

import (
	"database/sql"

	_ "github.com/go-sql-driver/mysql"
)

func Connect() (*sql.DB, error) {
	db, err := sql.Open("mysql", "root:@tcp(127.0.0.1:3306)/golang-redis-session")
	if err != nil {
		return nil, err
	}

	return db, nil
}
