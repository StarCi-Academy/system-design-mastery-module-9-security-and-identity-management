package com.starci.servicea;

import java.io.FileInputStream;
import java.net.http.HttpClient;
import java.security.KeyStore;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

// Builds two HttpClients for service-a:
//  - "trusted": loads the client KeyStore (service-a identity) AND the CA truststore,
//    so it presents a client cert during the handshake (authenticated call).
//  - "untrusted": loads ONLY the CA truststore (no client identity), so service-b
//    rejects the handshake — proving zero-trust.
@Configuration
public class MtlsClientConfig {

    private final String certsDir = System.getenv().getOrDefault("CERTS_DIR", "/certs");
    private final char[] storePass =
            System.getenv().getOrDefault("STOREPASS", "changeit").toCharArray();

    @Bean
    public HttpClient trustedClient() throws Exception {
        KeyStore keyStore = load("/client.p12");
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, storePass);

        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), trustManagers(), null);
        return HttpClient.newBuilder().sslContext(ctx).build();
    }

    @Bean
    public HttpClient untrustedClient() throws Exception {
        // No KeyManagers => no client certificate is presented.
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, trustManagers(), null);
        return HttpClient.newBuilder().sslContext(ctx).build();
    }

    private javax.net.ssl.TrustManager[] trustManagers() throws Exception {
        KeyStore trustStore = load("/truststore.p12");
        TrustManagerFactory tmf =
                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);
        return tmf.getTrustManagers();
    }

    private KeyStore load(String name) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (FileInputStream in = new FileInputStream(certsDir + name)) {
            ks.load(in, storePass);
        }
        return ks;
    }
}
