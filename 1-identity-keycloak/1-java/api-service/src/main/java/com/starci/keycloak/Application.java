/**
 * Identity & Keycloak lab — Spring Boot API service.
 * Spring Security OAuth2 Resource Server validates JWTs OFFLINE against the realm's
 * JWKS (auto-discovered from issuer-uri). Public + confidential client demo and a
 * protected /api/orders resource. English-only comments per repo convention.
 */
package com.starci.keycloak;

import java.util.List;
import java.util.Map;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;

@SpringBootApplication
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}

/** Resource server config — secure-by-default, offline JWT validation. */
@Configuration
@EnableWebSecurity
class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // Secure-by-default: every request needs a valid JWT except the explicitly permitted ones.
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/", "/auth/**").permitAll()
                .anyRequest().authenticated())
            // Resource server caches Keycloak's JWKS and validates each JWT signature offline.
            .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()))
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .csrf(csrf -> csrf.disable());
        return http.build();
    }
}

/** Token producer — password grant via public + confidential client. */
@Configuration
class KeycloakService {

    @Value("${keycloak.base-url:http://keycloak:8080}")
    private String baseUrl;
    @Value("${keycloak.realm:starci-realm}")
    private String realm;
    @Value("${keycloak.public-client-id:spring-app}")
    private String publicClientId;
    @Value("${keycloak.private-client-id:spring-private-app}")
    private String privateClientId;
    @Value("${keycloak.private-client-secret:super-secret-key}")
    private String privateClientSecret;
    @Value("${keycloak.redirect-uri:http://localhost:3000/auth/callback}")
    private String redirectUri;

    private final WebClient web = WebClient.builder().build();

    private String tokenEndpoint() {
        return baseUrl + "/realms/" + realm + "/protocol/openid-connect/token";
    }

    String authorizeUrl() {
        return baseUrl + "/realms/" + realm + "/protocol/openid-connect/auth"
            + "?client_id=" + publicClientId
            + "&response_type=code&scope=openid+profile+email"
            + "&redirect_uri=" + redirectUri
            + "&state=" + System.nanoTime();
    }

    @SuppressWarnings("unchecked")
    Map<String, Object> loginPublicClient(String username, String password) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("client_id", publicClientId);
        form.add("grant_type", "password");
        form.add("username", username);
        form.add("password", password);
        return fetchToken(form);
    }

    @SuppressWarnings("unchecked")
    Map<String, Object> loginPrivateClient(String username, String password) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("client_id", privateClientId);
        form.add("client_secret", privateClientSecret);
        form.add("grant_type", "password");
        form.add("username", username);
        form.add("password", password);
        return fetchToken(form);
    }

    @SuppressWarnings("unchecked")
    Map<String, Object> exchangeCode(String code) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("client_id", publicClientId);
        form.add("grant_type", "authorization_code");
        form.add("code", code);
        form.add("redirect_uri", redirectUri);
        return fetchToken(form);
    }

    // POST form-urlencoded to Keycloak's /token endpoint (JSON is rejected with 415).
    @SuppressWarnings("unchecked")
    private Map<String, Object> fetchToken(MultiValueMap<String, String> form) {
        return web.post()
            .uri(tokenEndpoint())
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .body(BodyInserters.fromFormData(form))
            .retrieve()
            .bodyToMono(Map.class)
            .block();
    }
}

/** Health probe + auth endpoints (all public). */
@RestController
class AuthController {

    private final KeycloakService keycloak;

    AuthController(KeycloakService keycloak) {
        this.keycloak = keycloak;
    }

    @GetMapping("/")
    public Map<String, Object> health() {
        return Map.of(
            "status", "ok",
            "message", "Identity Keycloak Spring Boot demo is running.",
            "endpoints", Map.of(
                "loginPublic", "POST /auth/login/public",
                "loginPrivate", "POST /auth/login/private",
                "authorizeUrl", "GET /auth/authorize/url",
                "authCallback", "GET /auth/callback?code=...",
                "protectedOrders", "GET /api/orders (requires Bearer token)"));
    }

    @PostMapping("/auth/login/public")
    public Map<String, Object> loginPublic(@RequestBody(required = false) Map<String, String> body) {
        return keycloak.loginPublicClient(value(body, "username", "student"), value(body, "password", "student123"));
    }

    @PostMapping("/auth/login/private")
    public Map<String, Object> loginPrivate(@RequestBody(required = false) Map<String, String> body) {
        return keycloak.loginPrivateClient(value(body, "username", "student"), value(body, "password", "student123"));
    }

    @GetMapping("/auth/authorize/url")
    public Map<String, Object> authorizeUrl() {
        return Map.of(
            "authorizeUrl", keycloak.authorizeUrl(),
            "note", "Open authorizeUrl in browser, then copy `code` from callback query params.");
    }

    @GetMapping("/auth/callback")
    public Map<String, Object> callback(@RequestParam(name = "code", required = false) String code) {
        return keycloak.exchangeCode(code == null ? "" : code);
    }

    private static String value(Map<String, String> body, String key, String def) {
        if (body == null) return def;
        String v = body.get(key);
        return (v == null || v.isEmpty()) ? def : v;
    }
}

/** Protected orders resource — the SecurityFilterChain already gates this path. */
@RestController
@RequestMapping("/api/orders")
class OrdersController {

    @GetMapping
    public Map<String, Object> listOrders(@AuthenticationPrincipal Jwt jwt) {
        String username = jwt.getClaimAsString("preferred_username");
        if (username == null) {
            username = jwt.getClaimAsString("email");
        }
        return Map.of(
            "status", "success",
            "message", "Welcome " + (username != null ? username : "user") + ". Here are your orders",
            "data", List.of(
                Map.of("id", 1, "total", 500),
                Map.of("id", 2, "total", 1000)));
    }
}
