package com.starci.envelopeapi;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.Optional;

@RestController
public class RecordsController {

    private final SecureRecordRepository repo;
    private final EnvelopeService envelope;

    public RecordsController(SecureRecordRepository repo, EnvelopeService envelope) {
        this.repo = repo;
        this.envelope = envelope;
    }

    /** POST /records — encrypt and store ciphertext + wrapped DEK. */
    @PostMapping("/records")
    public ResponseEntity<Map<String, Object>> create(@RequestBody Map<String, String> body) throws Exception {
        Map<String, String> env = envelope.encrypt(body.get("plaintext"));
        SecureRecord rec = new SecureRecord();
        rec.setWrappedDek(env.get("wrappedDek"));
        rec.setIv(env.get("iv"));
        rec.setCiphertext(env.get("ciphertext"));
        SecureRecord saved = repo.save(rec);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(Map.of("id", saved.getId(), "status", "encrypted"));
    }

    /** GET /records/{id} — unwrap the DEK, decrypt, return the plaintext (422 if KEK shredded). */
    @GetMapping("/records/{id}")
    public ResponseEntity<Map<String, Object>> findOne(@PathVariable Integer id) {
        Optional<SecureRecord> found = repo.findById(id);
        if (found.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("status", "not_found"));
        }
        SecureRecord rec = found.get();
        try {
            String plaintext = envelope.decrypt(rec.getWrappedDek(), rec.getIv(), rec.getCiphertext());
            return ResponseEntity.ok(Map.of("id", rec.getId(), "plaintext", plaintext));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY).body(Map.of("status", "unrecoverable"));
        }
    }

    /** POST /kek/rotate — bump the KEK version; old wrapped DEKs stay valid. */
    @PostMapping("/kek/rotate")
    public ResponseEntity<Map<String, Object>> rotate() {
        long version = envelope.rotateKek();
        return ResponseEntity.ok(Map.of("status", "rotated", "version", version));
    }

    /** POST /kek/shred — crypto-shredding: delete the KEK; all records become unrecoverable. */
    @PostMapping("/kek/shred")
    public ResponseEntity<Map<String, Object>> shred() {
        envelope.shredKek();
        return ResponseEntity.ok(Map.of("status", "shredded"));
    }
}
