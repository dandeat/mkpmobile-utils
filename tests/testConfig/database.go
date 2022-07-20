package testconfig

import (
	"database/sql"
	"fmt"
	_ "github.com/lib/pq"
	"time"
)

var db *sql.DB

// Open Connection
func OpenConnection() error {
	var err error
	db, err = setupConnection()

	return err
}

//setupConnection adalah
func setupConnection() (*sql.DB, error) {
	var connection = fmt.Sprintf("user=%s password=%s dbname=%s host=%s port=%s sslmode=%s",
		DBUser, DBPass, DBName, DBHost, DBPort, SSLMode)
	fmt.Println("Connection Info:", DBDriver, connection)

	db, err := sql.Open(DBDriver, connection)
	if err != nil {
		return db, err
	}

	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(30 * time.Second)

	return db, nil
}

//CloseConnectionDB adalah
func CloseConnectionDB() {
	db.Close()
}

//DBConnection adalah
func DBConnection() *sql.DB {
	return db
}
