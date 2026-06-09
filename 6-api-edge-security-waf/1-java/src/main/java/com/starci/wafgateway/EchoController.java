package com.starci.wafgateway;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

import java.util.Map;

// EchoController — the gateway route. Requests that survive the WAF filter are
// forwarded to the backend echo service, proving clean traffic passes through.
@RestController
public class EchoController {

    private final RestClient restClient;

    public EchoController() {
        String backendUrl = System.getenv().getOrDefault("BACKEND_URL", "http://localhost:4000");
        this.restClient = RestClient.create(backendUrl);
    }

    @GetMapping("/healthz")
    public Map<String, String> health() {
        return Map.of("status", "ok");
    }

    @PostMapping(value = "/api/echo", consumes = MediaType.ALL_VALUE)
    public ResponseEntity<Map<String, Object>> echo(@RequestBody(required = false) Object body) {
        // Forward the vetted payload to the backend and relay its response.
        Object echo = restClient.post()
                .uri("/echo")
                .contentType(MediaType.APPLICATION_JSON)
                .body(body == null ? Map.of() : body)
                .retrieve()
                .body(Object.class);
        return ResponseEntity.ok(Map.of("status", "allowed", "echo", echo));
    }
}
