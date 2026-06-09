package com.starci.auditapi;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import jakarta.annotation.PostConstruct;
import java.util.List;
import java.util.Map;

@Service
public class AuditService {

    private final JdbcTemplate jdbc;

    public AuditService(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @PostConstruct
    public void initSchema() {
        jdbc.execute("""
            CREATE TABLE IF NOT EXISTS audit_events (
                index INT PRIMARY KEY,
                actor VARCHAR NOT NULL,
                action VARCHAR NOT NULL,
                target VARCHAR NOT NULL,
                timestamp BIGINT NOT NULL,
                prev_hash VARCHAR(64) NOT NULL,
                entry_hash VARCHAR(64) NOT NULL
            )
            """);
    }

    // Append is serialized in a transaction with a table lock so two concurrent writers
    // cannot read the same tail and fork the chain.
    @Transactional
    public Map<String, Object> append(String actor, String action, String target) {
        jdbc.execute("LOCK TABLE audit_events IN EXCLUSIVE MODE");

        List<Map<String, Object>> last = jdbc.queryForList(
                "SELECT index, entry_hash FROM audit_events ORDER BY index DESC LIMIT 1");

        int index = 0;
        String prevHash = HashChain.GENESIS_PREV_HASH;
        if (!last.isEmpty()) {
            index = ((Number) last.get(0).get("index")).intValue() + 1;
            prevHash = (String) last.get(0).get("entry_hash");
        }

        long timestamp = System.currentTimeMillis();
        String entryHash = HashChain.computeEntryHash(index, prevHash, actor, action, target, timestamp);

        jdbc.update(
                "INSERT INTO audit_events (index, actor, action, target, timestamp, prev_hash, entry_hash) " +
                        "VALUES (?,?,?,?,?,?,?)",
                index, actor, action, target, timestamp, prevHash, entryHash);

        return Map.of("index", index, "prevHash", prevHash, "entryHash", entryHash);
    }

    // Verify walks the chain in order, recomputing each hash and checking linkage.
    public Map<String, Object> verify() {
        List<Map<String, Object>> rows = jdbc.queryForList(
                "SELECT index, actor, action, target, timestamp, prev_hash, entry_hash " +
                        "FROM audit_events ORDER BY index ASC");

        String expectedPrev = HashChain.GENESIS_PREV_HASH;
        for (Map<String, Object> row : rows) {
            int index = ((Number) row.get("index")).intValue();
            String prevHash = (String) row.get("prev_hash");
            String entryHash = (String) row.get("entry_hash");
            long timestamp = ((Number) row.get("timestamp")).longValue();
            String recomputed = HashChain.computeEntryHash(index, prevHash,
                    (String) row.get("actor"), (String) row.get("action"),
                    (String) row.get("target"), timestamp);

            if (!prevHash.equals(expectedPrev) || !recomputed.equals(entryHash)) {
                return Map.of("valid", false, "brokenIndex", index, "count", rows.size());
            }
            expectedPrev = entryHash;
        }
        return Map.of("valid", true, "count", rows.size());
    }
}
