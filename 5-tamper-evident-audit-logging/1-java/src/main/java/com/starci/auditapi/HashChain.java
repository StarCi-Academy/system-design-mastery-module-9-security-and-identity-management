package com.starci.auditapi;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Portable hash-chain core. The canonical serialization (fixed field order joined
 * with "|", then sha256 hex) MUST be byte-identical across all four languages.
 */
public final class HashChain {

    // The 64-zero genesis prevHash anchors the first entry — there is no row before index 0.
    public static final String GENESIS_PREV_HASH = "0".repeat(64);

    private HashChain() {
    }

    public static String computeEntryHash(int index, String prevHash, String actor,
                                          String action, String target, long timestamp) {
        String payload = index + "|" + prevHash + "|" + actor + "|" + action + "|" + target + "|" + timestamp;
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(payload.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(hash.length * 2);
            for (byte b : hash) {
                hex.append(Character.forDigit((b >> 4) & 0xF, 16));
                hex.append(Character.forDigit(b & 0xF, 16));
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
