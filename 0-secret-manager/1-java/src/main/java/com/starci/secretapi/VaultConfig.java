package com.starci.secretapi;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.vault.authentication.TokenAuthentication;
import org.springframework.vault.client.VaultEndpoint;
import org.springframework.vault.core.VaultTemplate;

import java.net.URI;

// Builds the VaultTemplate from VAULT_ADDR + VAULT_TOKEN (the secret-zero).
@Configuration
public class VaultConfig {

    @Bean
    public VaultTemplate vaultTemplate(Environment env) {
        String addr = env.getProperty("VAULT_ADDR", "http://localhost:8200");
        String token = env.getProperty("VAULT_TOKEN", "root");
        return new VaultTemplate(VaultEndpoint.from(URI.create(addr)), new TokenAuthentication(token));
    }
}
