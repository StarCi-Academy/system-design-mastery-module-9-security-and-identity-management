// Fine-grained authorization demo (Go) — the app externalizes every decision to OPA.
// An authz middleware builds the OPA input from request headers + the resource,
// calls OPA's HTTP decision API, and maps allow/deny to HTTP 200/403.
package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
)

// userContext holds the identity attributes extracted from request headers
// and serialised as the "user" field in the OPA input document.
type userContext struct {
	// ID is the unique user identifier (e.g. "alice"), mapped to input.user.id in Rego.
	ID         string   `json:"id"`
	// Roles is the list of role names (e.g. ["admin"]), mapped to input.user.roles.
	Roles      []string `json:"roles"`
	// Department is the organisational department, matched by the ABAC rule.
	Department string   `json:"department"`
	// Clearance is the numeric security level; Rego compares it with resource.sensitivity.
	Clearance  int      `json:"clearance"`
}

// resource represents a protected resource stored in the in-memory catalog
// and serialised as the "resource" field in the OPA input document.
type resource struct {
	// ID is the unique resource identifier (e.g. "report-finance").
	ID          string `json:"id"`
	// Type is the resource category (e.g. "report") — informational only.
	Type        string `json:"type"`
	// Owner is the user-id of the principal who owns the resource, used by ReBAC.
	Owner       string `json:"owner"`
	// Department is the organisational department the resource belongs to, used by ABAC.
	Department  string `json:"department"`
	// Sensitivity is the minimum clearance required for an ABAC read grant.
	Sensitivity int    `json:"sensitivity"`
}

// opaInput is the exact JSON document POSTed to OPA as the "input" field.
type opaInput struct {
	// User is the identity context for the requesting principal.
	User     userContext `json:"user"`
	// Action is the operation being attempted: read | write | delete.
	Action   string      `json:"action"`
	// Resource is the resource being acted upon.
	Resource resource    `json:"resource"`
}

// opaResult is the OPA response envelope for POST /v1/data/<path>.
type opaResult struct {
	// Result is present only when OPA evaluated a complete policy document.
	Result struct {
		// Allow is the policy verdict — true means the request is granted.
		Allow  bool   `json:"allow"`
		// Reason is the human-readable explanation from the Rego reason rule.
		Reason string `json:"reason"`
	} `json:"result"`
}

// resources is the in-memory resource catalog, identical to the other language tracks.
// Keyed by resource id for O(1) lookup in the request handler.
var resources = map[string]resource{
	// finance report — owned by alice, sensitivity 2 (medium)
	"report-finance": {ID: "report-finance", Type: "report", Owner: "alice", Department: "finance", Sensitivity: 2},
	// engineering report — owned by bob, sensitivity 3 (high)
	"report-eng":     {ID: "report-eng", Type: "report", Owner: "bob", Department: "engineering", Sensitivity: 3},
}

// evaluate asks OPA for an authorization decision; the app holds no policy logic itself.
// It wraps in in { "input": in }, POSTs to OPA's data API, and returns the verdict.
//
// opaBase is the base URL of the OPA service (e.g. "http://opa:8181").
// Returns allow, reason, and any transport/decode error.
func evaluate(opaBase string, in opaInput) (bool, string, error) {
	// Wrap in { "input": ... } — OPA binds the value to the `input` document in Rego.
	body, _ := json.Marshal(map[string]opaInput{"input": in})
	// POST to the data path that mirrors the Rego package name app.authz.
	resp, err := http.Post(opaBase+"/v1/data/app/authz", "application/json", bytes.NewReader(body))
	if err != nil {
		// Transport error — caller will return 502 so the denial is explicit, not silent.
		return false, "", err
	}
	defer resp.Body.Close()
	var out opaResult
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		// Decode failure — treat as a decision error, not a policy deny.
		return false, "", err
	}
	// Return only allow and reason; the rest of the OPA envelope is internal.
	return out.Result.Allow, out.Result.Reason, nil
}

// main registers the HTTP handlers and starts the server.
func main() {
	// Read OPA base URL from the environment; fall back to the docker-network hostname.
	opaBase := os.Getenv("OPA_BASE_URL")
	if opaBase == "" {
		opaBase = "http://opa:8181"
	}
	// Read port from the environment; default to 3000 for consistency with other tracks.
	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}

	// Liveness probe — not gated by any policy.
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		// Always returns ok; if the service is down this handler never executes.
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
	})

	// GET /documents/{id}/{action} — the authz middleware (policy enforcement point).
	http.HandleFunc("/documents/", func(w http.ResponseWriter, r *http.Request) {
		// Parse the two path segments: resource id and action.
		parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/documents/"), "/"), "/")
		if len(parts) != 2 {
			writeJSON(w, http.StatusNotFound, map[string]any{"status": "error", "message": "not found"})
			return
		}
		id, action := parts[0], parts[1]

		// Reject unknown resources before calling OPA to keep decisions scoped.
		res, ok := resources[id]
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]any{"status": "error", "message": "Unknown resource " + id})
			return
		}

		// Coerce clearance header to int — the Rego >= predicate compares numbers.
		clearance, _ := strconv.Atoi(r.Header.Get("x-user-clearance"))
		// Parse comma-separated roles header; nil slice is fine for Rego (empty set).
		var roles []string
		if raw := r.Header.Get("x-user-roles"); raw != "" {
			for _, p := range strings.Split(raw, ",") {
				roles = append(roles, strings.TrimSpace(p))
			}
		}
		// Build the OPA input document from headers + the looked-up resource.
		in := opaInput{
			User: userContext{
				ID:         r.Header.Get("x-user-id"),
				Roles:      roles,
				Department: r.Header.Get("x-user-department"),
				Clearance:  clearance,
			},
			Action:   action,
			Resource: res,
		}

		// Delegate the allow/deny decision entirely to OPA.
		allow, reason, err := evaluate(opaBase, in)
		if err != nil {
			// OPA unreachable — return 502 so the denial is explicit, not silently allowed.
			writeJSON(w, http.StatusBadGateway, map[string]any{"status": "error", "message": err.Error()})
			return
		}
		if !allow {
			// OPA denied — surface the policy reason so the caller knows which predicate failed.
			writeJSON(w, http.StatusForbidden, map[string]any{"status": "deny", "allowed": false, "reason": reason})
			return
		}
		// OPA allowed — echo back the decision for observability.
		writeJSON(w, http.StatusOK, map[string]any{
			"status": "allow", "allowed": true, "reason": reason, "resource": res.ID, "action": action,
		})
	})

	log.Printf("api-service listening on port %s", port)
	// ListenAndServe blocks; log.Fatal exits if the port is already in use.
	log.Fatal(http.ListenAndServe("0.0.0.0:"+port, nil))
}

// writeJSON serialises payload as JSON and writes it with the given HTTP status code.
// All response bodies go through this helper to ensure a consistent Content-Type.
func writeJSON(w http.ResponseWriter, code int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	// Encode directly to the response writer — no intermediate buffer needed.
	_ = json.NewEncoder(w).Encode(payload)
}
