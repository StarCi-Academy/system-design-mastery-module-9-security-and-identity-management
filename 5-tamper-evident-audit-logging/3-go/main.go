package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// genesisPrevHash anchors the first entry — there is no row before index 0.
const genesisPrevHash = "0000000000000000000000000000000000000000000000000000000000000000"

var pool *pgxpool.Pool

// computeEntryHash MUST be byte-identical to the other languages: fixed field order
// joined with "|", then sha256 hex. This is the portable core of the lesson.
func computeEntryHash(index int, prevHash, actor, action, target string, timestamp int64) string {
	payload := strings.Join([]string{
		strconv.Itoa(index), prevHash, actor, action, target, strconv.FormatInt(timestamp, 10),
	}, "|")
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

type appendDto struct {
	Actor  string `json:"actor"`
	Action string `json:"action"`
	Target string `json:"target"`
}

type appendResult struct {
	Index     int    `json:"index"`
	PrevHash  string `json:"prevHash"`
	EntryHash string `json:"entryHash"`
}

func orDefault(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

// appendHandler serializes the append in a transaction with a table lock so two
// concurrent writers cannot read the same tail and fork the chain.
func appendHandler(w http.ResponseWriter, r *http.Request) {
	var dto appendDto
	_ = json.NewDecoder(r.Body).Decode(&dto)
	actor := orDefault(dto.Actor, "unknown")
	action := orDefault(dto.Action, "unknown")
	target := orDefault(dto.Target, "unknown")

	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, "LOCK TABLE audit_events IN EXCLUSIVE MODE"); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var lastIndex int
	var lastHash string
	err = tx.QueryRow(ctx,
		"SELECT index, entry_hash FROM audit_events ORDER BY index DESC LIMIT 1").
		Scan(&lastIndex, &lastHash)

	index := 0
	prevHash := genesisPrevHash
	if err == nil {
		index = lastIndex + 1
		prevHash = lastHash
	}

	timestamp := time.Now().UnixMilli()
	entryHash := computeEntryHash(index, prevHash, actor, action, target, timestamp)

	if _, err := tx.Exec(ctx,
		`INSERT INTO audit_events (index, actor, action, target, timestamp, prev_hash, entry_hash)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		index, actor, action, target, timestamp, prevHash, entryHash); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(appendResult{Index: index, PrevHash: prevHash, EntryHash: entryHash})
}

// verifyHandler walks the chain in order, recomputing each hash and checking linkage.
func verifyHandler(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	rows, err := pool.Query(ctx,
		"SELECT index, actor, action, target, timestamp, prev_hash, entry_hash FROM audit_events ORDER BY index ASC")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	expectedPrev := genesisPrevHash
	count := 0
	brokenIndex := -1
	for rows.Next() {
		var index int
		var actor, action, target, prevHash, entryHash string
		var timestamp int64
		if err := rows.Scan(&index, &actor, &action, &target, &timestamp, &prevHash, &entryHash); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		count++
		// Record the FIRST broken row, then keep reading so count reflects the
		// whole table (the contract reports total rows, not rows-read-before-break).
		if brokenIndex == -1 {
			recomputed := computeEntryHash(index, prevHash, actor, action, target, timestamp)
			if prevHash != expectedPrev || recomputed != entryHash {
				brokenIndex = index
			}
			expectedPrev = entryHash
		}
	}
	w.Header().Set("Content-Type", "application/json")
	if brokenIndex != -1 {
		_ = json.NewEncoder(w).Encode(map[string]any{"valid": false, "brokenIndex": brokenIndex, "count": count})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"valid": true, "count": count})
}

func main() {
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%s/%s",
		orDefault(os.Getenv("DB_USER"), "admin"),
		orDefault(os.Getenv("DB_PASSWORD"), "123456"),
		orDefault(os.Getenv("DB_HOST"), "localhost"),
		orDefault(os.Getenv("DB_PORT"), "5432"),
		orDefault(os.Getenv("DB_NAME"), "auditdb"))

	ctx := context.Background()
	var err error
	pool, err = pgxpool.New(ctx, dsn)
	if err != nil {
		log.Fatalf("failed to create pool: %v", err)
	}
	// Retry until Postgres accepts connections, then ensure the schema exists.
	for i := 0; i < 30; i++ {
		if err = pool.Ping(ctx); err == nil {
			break
		}
		time.Sleep(time.Second)
	}
	if err != nil {
		log.Fatalf("postgres not reachable: %v", err)
	}
	if _, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS audit_events (
		index INT PRIMARY KEY,
		actor VARCHAR NOT NULL,
		action VARCHAR NOT NULL,
		target VARCHAR NOT NULL,
		timestamp BIGINT NOT NULL,
		prev_hash VARCHAR(64) NOT NULL,
		entry_hash VARCHAR(64) NOT NULL
	)`); err != nil {
		log.Fatalf("failed to create table: %v", err)
	}

	http.HandleFunc("/events", appendHandler)
	http.HandleFunc("/verify", verifyHandler)

	port := orDefault(os.Getenv("PORT"), "3000")
	log.Printf("audit-log-api listening on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
