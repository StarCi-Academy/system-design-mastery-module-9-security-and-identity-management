package com.starci.envelopeapi;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.vault.authentication.TokenAuthentication;
import org.springframework.vault.client.VaultEndpoint;
import org.springframework.vault.core.VaultTemplate;

import java.net.URI;

/**
 * Wires a VaultTemplate pointed at the Transit engine. The KEK lives only in Vault;
 * we use opsForTransit() to wrap/unwrap each per-record DEK.
 */
@Configuration
public class VaultConfig {

    @Bean
    public VaultTemplate vaultTemplate(@Value("${vault.addr}") String addr,
                                       @Value("${vault.token}") String token) {
        VaultEndpoint endpoint = VaultEndpoint.from(URI.create(addr));
        return new VaultTemplate(endpoint, new TokenAuthentication(token));
    }
}
