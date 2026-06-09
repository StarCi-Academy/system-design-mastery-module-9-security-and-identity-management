package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
)

// service-a — the mTLS client. It exposes a plain HTTP surface and calls service-b
// over mutual TLS. /call presents a valid client cert (authenticated 200);
// /call-no-cert presents none, so service-b rejects the handshake and we return 502.
func main() {
	certsDir := getenv("CERTS_DIR", "/certs")
	port := getenv("PORT", "3000")
	targetHost := getenv("SERVICE_B_HOST", "service-b")
	targetPort := getenv("SERVICE_B_PORT", "8443")
	target := "https://" + targetHost + ":" + targetPort + "/secure"

	caPEM, err := os.ReadFile(certsDir + "/ca.crt")
	if err != nil {
		log.Fatalf("[service-a] cannot read CA: %v", err)
	}
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caPEM)

	// Client WITH its certificate — used for the authenticated call.
	clientCert, err := tls.LoadX509KeyPair(certsDir+"/client.crt", certsDir+"/client.key")
	if err != nil {
		log.Fatalf("[service-a] cannot load client cert: %v", err)
	}
	trustedClient := newClient(caPool, []tls.Certificate{clientCert})

	// Client WITHOUT a certificate — used to prove the zero-trust rejection.
	untrustedClient := newClient(caPool, nil)

	mux := http.NewServeMux()

	mux.HandleFunc("/call", func(w http.ResponseWriter, r *http.Request) {
		body, err := fetch(trustedClient, target)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]any{
				"status": "rejected", "authenticated": false, "reason": err.Error(),
			})
			return
		}
		// Forward service-b's body verbatim.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	})

	mux.HandleFunc("/call-no-cert", func(w http.ResponseWriter, r *http.Request) {
		_, err := fetch(untrustedClient, target)
		if err != nil {
			// Expected zero-trust outcome: handshake aborted by service-b.
			writeJSON(w, http.StatusBadGateway, map[string]any{
				"status": "rejected", "authenticated": false, "reason": err.Error(),
			})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"status": "unexpected", "authenticated": false,
		})
	})

	log.Printf("[service-a] listening on :%s -> %s", port, target)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatalf("[service-a] server error: %v", err)
	}
}

func newClient(caPool *x509.CertPool, certs []tls.Certificate) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      caPool,
				Certificates: certs,
				ServerName:   "service-b", // Match the server cert SAN/CN.
			},
		},
	}
}

func fetch(c *http.Client, url string) ([]byte, error) {
	resp, err := c.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

func writeJSON(w http.ResponseWriter, code int, payload map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(payload)
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
