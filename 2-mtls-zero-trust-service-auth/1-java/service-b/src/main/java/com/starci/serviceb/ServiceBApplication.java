package com.starci.serviceb;

import java.security.cert.X509Certificate;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

// service-b — the mTLS server. SSL is configured in application.properties with
// server.ssl.client-auth=need, so embedded Tomcat REQUIRES and verifies a client
// certificate (chained to the internal CA truststore) before any handler runs.
@SpringBootApplication
@RestController
public class ServiceBApplication {

    public static void main(String[] args) {
        SpringApplication.run(ServiceBApplication.class, args);
    }

    @GetMapping("/secure")
    public Map<String, Object> secure(HttpServletRequest request) {
        // Reaching here proves the client cert already passed CA verification.
        String caller = "unknown";
        X509Certificate[] certs =
                (X509Certificate[]) request.getAttribute("jakarta.servlet.request.X509Certificate");
        if (certs != null && certs.length > 0) {
            // Extract the CN from the subject DN, e.g. "CN=service-a,O=StarCi-Internal".
            caller = certs[0].getSubjectX500Principal().getName().replaceAll(".*CN=([^,]+).*", "$1");
        }
        return Map.of("status", "ok", "caller", caller, "authenticated", true);
    }
}
