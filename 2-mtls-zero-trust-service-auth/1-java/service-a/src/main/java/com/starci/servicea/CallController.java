package com.starci.servicea;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Map;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

// service-a's HTTP surface. /call presents a valid client cert (authenticated 200);
// /call-no-cert presents none, so service-b rejects the handshake and we return 502.
@RestController
public class CallController {

    private final HttpClient trustedClient;
    private final HttpClient untrustedClient;
    private final String target;

    public CallController(HttpClient trustedClient, HttpClient untrustedClient) {
        this.trustedClient = trustedClient;
        this.untrustedClient = untrustedClient;
        String host = System.getenv().getOrDefault("SERVICE_B_HOST", "service-b");
        String port = System.getenv().getOrDefault("SERVICE_B_PORT", "8443");
        this.target = "https://" + host + ":" + port + "/secure";
    }

    @GetMapping(value = "/call", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> call() throws Exception {
        HttpResponse<String> resp = send(trustedClient);
        // Forward service-b's body verbatim.
        return ResponseEntity.ok(resp.body());
    }

    @GetMapping(value = "/call-no-cert", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> callNoCert() {
        try {
            send(untrustedClient);
            return ResponseEntity.status(500)
                    .body(Map.of("status", "unexpected", "authenticated", false));
        } catch (Exception e) {
            // Expected zero-trust outcome: handshake aborted by service-b.
            return ResponseEntity.status(502)
                    .body(Map.of("status", "rejected", "authenticated", false,
                            "reason", String.valueOf(e.getMessage())));
        }
    }

    private HttpResponse<String> send(HttpClient client) throws Exception {
        HttpRequest req = HttpRequest.newBuilder(URI.create(target)).GET().build();
        return client.send(req, HttpResponse.BodyHandlers.ofString());
    }
}
