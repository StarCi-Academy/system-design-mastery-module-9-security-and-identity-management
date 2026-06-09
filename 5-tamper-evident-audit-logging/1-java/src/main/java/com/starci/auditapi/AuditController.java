package com.starci.auditapi;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class AuditController {

    private final AuditService auditService;

    public AuditController(AuditService auditService) {
        this.auditService = auditService;
    }

    // POST /events — append one event, returning index + the two hashes (HTTP 201).
    @PostMapping("/events")
    public ResponseEntity<Map<String, Object>> append(@RequestBody(required = false) Map<String, String> body) {
        Map<String, String> b = body == null ? Map.of() : body;
        String actor = b.getOrDefault("actor", "unknown");
        String action = b.getOrDefault("action", "unknown");
        String target = b.getOrDefault("target", "unknown");
        return ResponseEntity.status(HttpStatus.CREATED).body(auditService.append(actor, action, target));
    }

    // GET /verify — recompute the chain and report OK or the first broken index.
    @GetMapping("/verify")
    public Map<String, Object> verify() {
        return auditService.verify();
    }
}
