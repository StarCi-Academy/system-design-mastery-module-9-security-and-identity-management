package com.starci.fga;

import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

/**
 * OpaService asks OPA for an authorization decision over HTTP.
 * The app holds no policy logic — it builds the input document and delegates
 * every allow/deny decision to OPA's data API at {@code /v1/data/app/authz}.
 */
@Service
public class OpaService {

    /** Spring's HTTP client — synchronous, suitable for the per-request OPA call. */
    private final RestTemplate rest = new RestTemplate();

    /** Full URL to the OPA data path that maps to package app.authz. */
    private final String url;

    /**
     * Construct OpaService, resolving the OPA base URL from the environment.
     *
     * @param baseUrl Value of {@code opa.base-url} in application.properties;
     *                defaults to {@code http://opa:8181} (docker-network hostname).
     */
    public OpaService(@Value("${opa.base-url:http://opa:8181}") String baseUrl) {
        // Append the data path: /v1/data/app/authz mirrors the Rego package name.
        this.url = baseUrl + "/v1/data/app/authz";
    }

    /**
     * The allow/deny verdict returned by OPA for a single request.
     *
     * @param allow  Whether the policy granted the request.
     * @param reason Human-readable reason from the Rego reason rule.
     */
    public record Decision(boolean allow, String reason) {}

    /**
     * Evaluate an OPA input document and return the authorization decision.
     *
     * @param input The context document (user + action + resource) for this request.
     * @return The decision containing allow flag and policy reason.
     * @throws IllegalStateException when OPA returned no decision document.
     */
    @SuppressWarnings("unchecked")
    public Decision evaluate(Models.OpaInput input) {
        // Wrap in { "input": ... } — OPA binds the value to the `input` document in Rego.
        Map<String, Object> body = Map.of("input", input);
        Map<String, Object> response = rest.postForObject(url, body, Map.class);
        if (response == null || response.get("result") == null) {
            // No result document means the policy package failed to load or path is wrong.
            throw new IllegalStateException("OPA returned no decision for data.app.authz");
        }
        Map<String, Object> result = (Map<String, Object>) response.get("result");
        // Cast the raw Map values — OPA always returns a boolean allow and string reason.
        boolean allow = Boolean.TRUE.equals(result.get("allow"));
        String reason = String.valueOf(result.get("reason"));
        return new Decision(allow, reason);
    }
}
