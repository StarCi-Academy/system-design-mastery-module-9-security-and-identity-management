package com.starci.envelopeapi;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.core.VaultTransitOperations;
import org.springframework.vault.support.VaultTransitKeyCreationRequest;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * Two-tier envelope encryption:
 *   data ──AES-256-GCM──▶ encrypted by a per-record DEK (generated locally)
 *   DEK  ──Transit wrap──▶ encrypted by the KEK (lives only in Vault)
 * Bulk data never touches Vault; only the 32-byte DEK is wrapped/unwrapped.
 */
@Service
public class EnvelopeService {

    private final VaultTemplate vaultTemplate;
    private final VaultTransitOperations transit;
    private final String kek;
    private final SecureRandom random = new SecureRandom();

    public EnvelopeService(VaultTemplate vaultTemplate, @Value("${vault.kek}") String kek) {
        this.vaultTemplate = vaultTemplate;
        this.transit = vaultTemplate.opsForTransit();
        this.kek = kek;
    }

    @PostConstruct
    public void ensureKek() {
        // Enable the Transit secrets engine first (idempotent; ignore "already mounted" 400).
        try {
            java.util.Map<String, Object> mountBody = new java.util.HashMap<>();
            mountBody.put("type", "transit");
            vaultTemplate.write("sys/mounts/transit", mountBody);
        } catch (Exception ignored) {
            // Already mounted — fine.
        }
        // Creating an existing key is idempotent in Vault Transit.
        try {
            transit.createKey(kek, VaultTransitKeyCreationRequest.builder().type("aes256-gcm96").build());
        } catch (Exception ignored) {
            // Already exists — fine.
        }
    }

    public Map<String, String> encrypt(String plaintext) throws Exception {
        // 1. Fresh 256-bit DEK + 96-bit GCM nonce for THIS record only.
        byte[] dek = new byte[32];
        random.nextBytes(dek);
        byte[] iv = new byte[12];
        random.nextBytes(iv);

        // 2. Encrypt the bulk data locally — Vault never sees the plaintext.
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(dek, "AES"), new GCMParameterSpec(128, iv));
        byte[] sealed = cipher.doFinal(plaintext.getBytes()); // ciphertext||authTag

        // 3. Wrap the DEK with the KEK inside Vault.
        String wrapped = transit.encrypt(kek, Base64.getEncoder().encodeToString(dek));

        Map<String, String> out = new HashMap<>();
        out.put("wrappedDek", wrapped);
        out.put("iv", Base64.getEncoder().encodeToString(iv));
        out.put("ciphertext", Base64.getEncoder().encodeToString(sealed));
        return out;
    }

    public String decrypt(String wrappedDek, String ivB64, String ctB64) throws Exception {
        // 1. Ask Vault to unwrap the DEK (works across KEK versions after rotation).
        byte[] dek = Base64.getDecoder().decode(transit.decrypt(kek, wrappedDek));
        byte[] iv = Base64.getDecoder().decode(ivB64);
        byte[] sealed = Base64.getDecoder().decode(ctB64);

        // 2. Decrypt locally with the recovered DEK.
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(dek, "AES"), new GCMParameterSpec(128, iv));
        return new String(cipher.doFinal(sealed));
    }

    public long rotateKek() {
        transit.rotate(kek);
        Map<String, Object> data = vaultTemplate.read("transit/keys/" + kek).getData();
        return ((Number) data.get("latest_version")).longValue();
    }

    public void shredKek() {
        // Crypto-shredding: allow deletion, then delete the KEK so no DEK can be unwrapped again.
        Map<String, Object> cfg = new HashMap<>();
        cfg.put("deletion_allowed", true);
        vaultTemplate.write("transit/keys/" + kek + "/config", cfg);
        vaultTemplate.delete("transit/keys/" + kek);
    }
}
