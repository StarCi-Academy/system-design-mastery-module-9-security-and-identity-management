package com.starci.secretapi;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.support.Versioned;

import java.util.Map;

// Reads DB_PASSWORD from HashiCorp Vault (KV v2) at runtime, not from a static config value.
@Service
public class VaultSecretService {
    private static final Logger log = LoggerFactory.getLogger(VaultSecretService.class);

    private final VaultTemplate vaultTemplate;
    // Same VAULT_ADDR the VaultTemplate is built from; used only to log the resolved KV v2 path.
    private final String vaultAddr;

    public VaultSecretService(VaultTemplate vaultTemplate, Environment env) {
        this.vaultTemplate = vaultTemplate;
        this.vaultAddr = env.getProperty("VAULT_ADDR", "http://localhost:8200");
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    public String fetchDatabasePassword() {
        log.info("Fetching secret from Vault at {}/v1/secret/data/my-app...", vaultAddr);

        // Read the secret over Vault's KV v2 API at runtime, not from a static config value.
        Versioned<Map<String, Object>> response =
                vaultTemplate.opsForVersionedKeyValue("secret").get("my-app", (Class) Map.class);

        // KV v2 wraps the payload: getData() returns the inner data map = values.
        Object password = response != null && response.getData() != null
                ? response.getData().get("DB_PASSWORD")
                : null;
        if (password == null) {
            throw new IllegalStateException("DB_PASSWORD not found in Vault secret.");
        }

        log.info("Successfully retrieved DB_PASSWORD from Vault.");
        return password.toString();
    }
}
