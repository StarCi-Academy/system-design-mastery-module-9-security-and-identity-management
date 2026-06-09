package com.starci.fga;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

/**
 * DocumentsController is the authz middleware: it builds the OPA input from
 * request headers + the resource, asks OPA for a decision, and maps allow/deny
 * to HTTP 200/403. It contains no policy logic.
 */
@RestController
public class DocumentsController {

    /** OPA client — the single point of contact with the policy engine. */
    private final OpaService opa;

    /**
     * Inject OpaService via constructor injection (preferred over field injection).
     *
     * @param opa The service that delegates all decisions to OPA.
     */
    public DocumentsController(OpaService opa) {
        this.opa = opa;
    }

    /**
     * Liveness probe — not gated by any policy.
     *
     * @return Static {@code {"status": "ok"}} map confirming the service is running.
     */
    @GetMapping("/health")
    public Map<String, String> health() {
        // Always returns ok; if the service is down this handler never executes.
        return Map.of("status", "ok");
    }

    /**
     * Enforce access control on a document action.
     * Reads identity from {@code x-user-*} headers, builds the OPA input, and
     * returns 403 when OPA denies the request.
     *
     * @param id         Document resource id (e.g. "report-finance").
     * @param action     Attempted action: read | write | delete.
     * @param userId     Value of {@code x-user-id} header.
     * @param roles      Comma-separated roles from {@code x-user-roles} header.
     * @param department Department from {@code x-user-department} header.
     * @param clearance  Numeric clearance from {@code x-user-clearance} header.
     * @return HTTP 200 with allow body, or HTTP 403/404 with error body.
     */
    @GetMapping("/documents/{id}/{action}")
    public ResponseEntity<Map<String, Object>> access(
            @PathVariable String id,
            @PathVariable String action,
            @RequestHeader(value = "x-user-id", required = false, defaultValue = "") String userId,
            @RequestHeader(value = "x-user-roles", required = false, defaultValue = "") String roles,
            @RequestHeader(value = "x-user-department", required = false, defaultValue = "") String department,
            @RequestHeader(value = "x-user-clearance", required = false, defaultValue = "0") String clearance) {

        // Reject unknown resources before calling OPA to keep decisions scoped.
        Models.Resource resource = Models.RESOURCES.get(id);
        if (resource == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of("status", "error", "message", "Unknown resource " + id));
        }

        // Parse the comma-separated roles header into a list; empty string → empty list.
        List<String> roleList = roles.isBlank()
                ? List.of()
                : Arrays.stream(roles.split(",")).map(String::trim).toList();
        // Coerce clearance to int — the Rego >= predicate compares numbers.
        Models.UserContext user = new Models.UserContext(userId, roleList, department, parseInt(clearance));

        // Delegate the allow/deny decision entirely to OPA.
        OpaService.Decision decision = opa.evaluate(new Models.OpaInput(user, action, resource));
        if (!decision.allow()) {
            // OPA denied — surface the policy reason so the caller knows which predicate failed.
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of("status", "deny", "allowed", false, "reason", decision.reason()));
        }

        // OPA allowed — echo back the decision for observability.
        return ResponseEntity.ok(Map.of(
                "status", "allow",
                "allowed", true,
                "reason", decision.reason(),
                "resource", resource.id(),
                "action", action));
    }

    /**
     * Parse a string as an integer, returning 0 on any parse failure.
     * Prevents NumberFormatException from malformed clearance header values.
     *
     * @param value Raw string from the HTTP header.
     * @return Parsed integer, or 0 if the value is blank or non-numeric.
     */
    private static int parseInt(String value) {
        try {
            return Integer.parseInt(value.trim());
        } catch (NumberFormatException e) {
            // Non-numeric clearance defaults to 0 — lowest clearance, safest fallback.
            return 0;
        }
    }
}
