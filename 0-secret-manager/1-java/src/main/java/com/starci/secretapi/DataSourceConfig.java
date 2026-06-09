package com.starci.secretapi;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

import javax.sql.DataSource;

// Defines the DataSource bean ourselves so the Vault fetch runs BEFORE the Hikari pool opens.
@Configuration
public class DataSourceConfig {

    @Bean
    public DataSource dataSource(VaultSecretService vaultSecretService, Environment env) {
        // Resolve the runtime Vault fetch BEFORE materializing the Hikari pool.
        String dbPassword = vaultSecretService.fetchDatabasePassword();

        HikariConfig config = new HikariConfig();
        config.setJdbcUrl("jdbc:postgresql://"
                + env.getProperty("DB_HOST", "localhost") + ":"
                + env.getProperty("DB_PORT", "5432") + "/"
                + env.getProperty("DB_NAME", "userdb"));
        config.setUsername(env.getProperty("DB_USER", "admin"));
        config.setPassword(dbPassword);
        return new HikariDataSource(config);
    }
}
