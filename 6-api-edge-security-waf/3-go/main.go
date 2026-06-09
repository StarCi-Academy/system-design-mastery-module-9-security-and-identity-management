package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
)

// WAF gateway in Go — the API edge. The wafMiddleware inspects query, headers,
// and JSON body before any handler runs; clean traffic is proxied to the
// backend echo service, malicious traffic is blocked 403.

func writeJSON(w http.ResponseWriter, status int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// wafMiddleware is the API-edge filter applied to every route.
func wafMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Inspect every query-string value.
		for _, values := range r.URL.Query() {
			for _, value := range values {
				if hit := inspectValue(value); hit != "" {
					block(w, r, hit)
					return
				}
			}
		}

		// 2. Inspect user-controlled headers.
		if hit := inspectValue(r.Header.Get("X-Forwarded-For")); hit != "" {
			block(w, r, hit)
			return
		}
		if hit := inspectValue(r.Header.Get("Referer")); hit != "" {
			block(w, r, hit)
			return
		}

		// 3. Inspect the JSON body recursively, then restore it for the handler.
		if r.Body != nil {
			raw, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(raw))
			if len(raw) > 0 {
				var payload interface{}
				if json.Unmarshal(raw, &payload) == nil {
					if hit := inspectPayload(payload); hit != "" {
						block(w, r, hit)
						return
					}
				}
			}
		}

		next.ServeHTTP(w, r)
	})
}

func block(w http.ResponseWriter, r *http.Request, rule string) {
	log.Printf("BLOCKED %s %s rule=%s", r.Method, r.URL.Path, rule)
	// Uniform 403 contract — never echo the offending payload back.
	writeJSON(w, http.StatusForbidden, map[string]string{"status": "blocked", "rule": rule})
}

func main() {
	backendURL := os.Getenv("BACKEND_URL")
	if backendURL == "" {
		backendURL = "http://localhost:4000"
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	mux.HandleFunc("/api/echo", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		// Forward the vetted payload to the backend and relay its response.
		raw, _ := io.ReadAll(r.Body)
		resp, err := http.Post(backendURL+"/echo", "application/json", bytes.NewReader(raw))
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "backend unreachable"})
			return
		}
		defer resp.Body.Close()
		var echo interface{}
		_ = json.NewDecoder(resp.Body).Decode(&echo)
		writeJSON(w, http.StatusOK, map[string]interface{}{"status": "allowed", "echo": echo})
	})

	log.Printf("WAF gateway listening on :%s", port)
	if err := http.ListenAndServe(":"+port, wafMiddleware(mux)); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}
