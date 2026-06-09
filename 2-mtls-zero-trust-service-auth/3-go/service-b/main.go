package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"log"
	"net/http"
	"os"
)

// service-b — the mTLS server. crypto/tls is told to REQUIRE and VERIFY a client
// certificate signed by the internal CA. Without one, the handshake is aborted
// before any HTTP handler runs (zero-trust at the transport layer).
func main() {
	certsDir := getenv("CERTS_DIR", "/certs")
	port := getenv("PORT", "8443")

	// Load the CA bundle used to verify the client certificate.
	caPEM, err := os.ReadFile(certsDir + "/ca.crt")
	if err != nil {
		log.Fatalf("[service-b] cannot read CA: %v", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		log.Fatalf("[service-b] failed to parse CA bundle")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/secure", func(w http.ResponseWriter, r *http.Request) {
		// Reaching here proves the client cert already passed CA verification.
		caller := "unknown"
		if len(r.TLS.PeerCertificates) > 0 {
			caller = r.TLS.PeerCertificates[0].Subject.CommonName
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":        "ok",
			"caller":        caller,
			"authenticated": true,
		})
	})

	server := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
		TLSConfig: &tls.Config{
			ClientCAs:  caPool,
			ClientAuth: tls.RequireAndVerifyClientCert, // The zero-trust switch.
			MinVersion: tls.VersionTLS12,
		},
	}

	log.Printf("[service-b] mTLS server listening on :%s (RequireAndVerifyClientCert)", port)
	// Cert/key paths are the server's own identity presented to clients.
	if err := server.ListenAndServeTLS(certsDir+"/server.crt", certsDir+"/server.key"); err != nil {
		log.Fatalf("[service-b] server error: %v", err)
	}
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
