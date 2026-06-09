package com.starci.fga;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Fine-grained authorization demo (Spring Boot).
 * The app externalizes every authorization decision to OPA via its HTTP decision API;
 * it holds no policy logic itself — only the enforcement point (build input, map 200/403).
 */
@SpringBootApplication
public class FgaApplication {

    /**
     * Application entry point — delegates startup to Spring Boot.
     *
     * @param args Command-line arguments passed to Spring Boot's context builder.
     */
    public static void main(String[] args) {
        // SpringApplication.run bootstraps the application context, starts Tomcat,
        // and wires all @Component / @Service / @RestController beans.
        SpringApplication.run(FgaApplication.class, args);
    }
}
