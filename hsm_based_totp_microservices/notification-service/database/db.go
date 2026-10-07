package database

import (
	"database/sql"
	"fmt"
	"log"
	"notificationservice/config"

	_ "github.com/lib/pq"
)

var DB *sql.DB

func ConnectDB(cfg *config.Config) {

	connStr := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		cfg.DBHost,
		cfg.DBPort,
		cfg.DBUser,
		cfg.DBPass,
		cfg.DBName,
	)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal("❌ DB connection error:", err)
	}

	if err := db.Ping(); err != nil {
		log.Fatal("❌ DB ping error:", err)
	}

	DB = db

	log.Println("✅ Notification DB connected")
}
