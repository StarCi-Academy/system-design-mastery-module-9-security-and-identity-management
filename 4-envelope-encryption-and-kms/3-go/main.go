package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	vault "github.com/hashicorp/vault/api"
	"github.com/jackc/pgx/v5/pgxpool"
)

// kekName is the Transit key that wraps every per-record DEK. It never leaves Vault.
var (
	kekName = env("KEK_NAME", "app-kek")
	vc      *vault.Client
	db      *pgxpool.Pool
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// wrapDek sends the raw DEK to Vault Transit and gets back a "vault:vN:..." blob.
func wrapDek(rawDek []byte) (string, error) {
	secret, err := vc.Logical().Write("transit/encrypt/"+kekName, map[string]interface{}{
		"plaintext": base64.StdEncoding.EncodeToString(rawDek),
	})
	if err != nil {
		return "", err
	}
	return secret.Data["ciphertext"].(string), nil
}

// unwrapDek asks Vault to decrypt the wrapped DEK back to raw key bytes.
func unwrapDek(wrapped string) ([]byte, error) {
	secret, err := vc.Logical().Write("transit/decrypt/"+kekName, map[string]interface{}{
		"ciphertext": wrapped,
	})
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(secret.Data["plaintext"].(string))
}

// createRecord generates a DEK, AES-GCM encrypts the data, wraps the DEK, stores the envelope.
func createRecord(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Plaintext string `json:"plaintext"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	dek := make([]byte, 32)
	rand.Read(dek)
	iv := make([]byte, 12)
	rand.Read(iv)

	block, _ := aes.NewCipher(dek)
	gcm, _ := cipher.NewGCM(block)
	sealed := gcm.Seal(nil, iv, []byte(body.Plaintext), nil) // ciphertext||authTag

	wrapped, err := wrapDek(dek)
	if err != nil {
		http.Error(w, "wrap failed", http.StatusInternalServerError)
		return
	}

	var id int
	err = db.QueryRow(context.Background(),
		`INSERT INTO secure_records (wrapped_dek, iv, ciphertext) VALUES ($1,$2,$3) RETURNING id`,
		wrapped, base64.StdEncoding.EncodeToString(iv), base64.StdEncoding.EncodeToString(sealed),
	).Scan(&id)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{"id": id, "status": "encrypted"})
}

// getRecord unwraps the DEK and AES-GCM decrypts. If the KEK was shredded, returns 422.
func getRecord(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var wrapped, ivB64, ctB64 string
	err := db.QueryRow(context.Background(),
		`SELECT wrapped_dek, iv, ciphertext FROM secure_records WHERE id=$1`, id,
	).Scan(&wrapped, &ivB64, &ctB64)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"status": "not_found"})
		return
	}

	dek, err := unwrapDek(wrapped)
	if err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"status": "unrecoverable"})
		return
	}
	iv, _ := base64.StdEncoding.DecodeString(ivB64)
	sealed, _ := base64.StdEncoding.DecodeString(ctB64)
	block, _ := aes.NewCipher(dek)
	gcm, _ := cipher.NewGCM(block)
	plain, err := gcm.Open(nil, iv, sealed, nil)
	if err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"status": "unrecoverable"})
		return
	}
	idInt := 0
	fmt.Sscan(id, &idInt)
	writeJSON(w, http.StatusOK, map[string]interface{}{"id": idInt, "plaintext": string(plain)})
}

// rotateKek bumps the KEK version; old wrapped DEKs stay decryptable.
func rotateKek(w http.ResponseWriter, r *http.Request) {
	if _, err := vc.Logical().Write("transit/keys/"+kekName+"/rotate", nil); err != nil {
		http.Error(w, "rotate failed", http.StatusInternalServerError)
		return
	}
	read, _ := vc.Logical().Read("transit/keys/" + kekName)
	version, _ := read.Data["latest_version"].(json.Number).Int64()
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "rotated", "version": version})
}

// shredKek deletes the KEK — every wrapped DEK becomes permanently unrecoverable.
func shredKek(w http.ResponseWriter, r *http.Request) {
	vc.Logical().Write("transit/keys/"+kekName+"/config", map[string]interface{}{"deletion_allowed": true})
	if _, err := vc.Logical().Delete("transit/keys/" + kekName); err != nil {
		http.Error(w, "shred failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "shredded"})
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

// ensureKek enables Transit and creates the KEK (idempotent) at boot.
func ensureKek() {
	vc.Logical().Write("sys/mounts/transit", map[string]interface{}{"type": "transit"})
	vc.Logical().Write("transit/keys/"+kekName, map[string]interface{}{"type": "aes256-gcm96"})
}

func main() {
	cfg := vault.DefaultConfig()
	cfg.Address = env("VAULT_ADDR", "http://localhost:8200")
	var err error
	vc, err = vault.NewClient(cfg)
	if err != nil {
		log.Fatalf("vault client: %v", err)
	}
	vc.SetToken(env("VAULT_TOKEN", "root"))
	ensureKek()

	dsn := fmt.Sprintf("postgres://%s:%s@%s:%s/%s",
		env("DB_USER", "admin"), env("DB_PASSWORD", "123456"),
		env("DB_HOST", "localhost"), env("DB_PORT", "5432"), env("DB_NAME", "vaultdb"))
	db, err = pgxpool.New(context.Background(), dsn)
	if err != nil {
		log.Fatalf("db connect: %v", err)
	}
	db.Exec(context.Background(),
		`CREATE TABLE IF NOT EXISTS secure_records (id SERIAL PRIMARY KEY, wrapped_dek TEXT, iv TEXT, ciphertext TEXT)`)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /records", createRecord)
	mux.HandleFunc("GET /records/{id}", getRecord)
	mux.HandleFunc("POST /kek/rotate", rotateKek)
	mux.HandleFunc("POST /kek/shred", shredKek)

	port := env("PORT", "3000")
	log.Printf("envelope-api listening on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}
