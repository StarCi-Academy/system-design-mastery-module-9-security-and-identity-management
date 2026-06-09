package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"

	vault "github.com/hashicorp/vault/api"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// fetchDatabasePassword reads the secret over Vault's HTTP API at runtime,
// not from a static env var. The vault/api client auto-unwraps the KV v2 envelope.
func fetchDatabasePassword(ctx context.Context) (string, error) {
	vaultAddr := getenv("VAULT_ADDR", "http://localhost:8200")
	vaultToken := getenv("VAULT_TOKEN", "root")

	cfg := vault.DefaultConfig()
	cfg.Address = vaultAddr
	client, err := vault.NewClient(cfg)
	if err != nil {
		return "", err
	}
	client.SetToken(vaultToken)

	log.Printf("Fetching secret from Vault at %s/v1/secret/data/my-app...", vaultAddr)

	// KVv2(...).Get returns secret.Data already unwrapped to the inner "data" map;
	// secret.VersionMetadata still carries the version (for rollback).
	secret, err := client.KVv2("secret").Get(ctx, "my-app")
	if err != nil {
		return "", err
	}
	password, ok := secret.Data["DB_PASSWORD"].(string)
	if !ok || password == "" {
		return "", errors.New("DB_PASSWORD not found in Vault secret")
	}
	log.Println("Successfully retrieved DB_PASSWORD from Vault.")
	return password, nil
}

type user struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

func seed(db *sql.DB) error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, name TEXT NOT NULL)`); err != nil {
		return err
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count); err != nil {
		return err
	}
	if count == 0 {
		if _, err := db.Exec(`INSERT INTO users (name) VALUES ($1), ($2)`, "Admin StarCi", "Học viên VIP"); err != nil {
			return err
		}
	}
	return nil
}

// GET /users — proves the Vault-sourced password opened a real DB connection.
func usersHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rows, err := db.Query(`SELECT id, name FROM users ORDER BY id`)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		users := []user{}
		for rows.Next() {
			var u user
			if err := rows.Scan(&u.ID, &u.Name); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			users = append(users, u)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": users})
	}
}

func main() {
	ctx := context.Background()

	// Await the runtime Vault fetch BEFORE building the DSN / opening the pool.
	dbPassword, err := fetchDatabasePassword(ctx)
	if err != nil {
		log.Fatalf("vault fetch failed: %v", err) // fail-fast: refuse to start
	}

	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		getenv("DB_HOST", "localhost"),
		getenv("DB_PORT", "5432"),
		getenv("DB_USER", "admin"),
		dbPassword, // only the sensitive value comes from Vault
		getenv("DB_NAME", "userdb"),
	)
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	if err := db.Ping(); err != nil {
		log.Fatalf("ping db: %v", err) // wrong password burns Postgres connections
	}
	if err := seed(db); err != nil {
		log.Fatalf("seed db: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/users", usersHandler(db))

	port := getenv("PORT", "3000")
	log.Printf("secret-api listening on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}
