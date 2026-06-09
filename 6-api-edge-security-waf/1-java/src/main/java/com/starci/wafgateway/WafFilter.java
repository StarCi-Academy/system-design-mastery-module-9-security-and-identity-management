package com.starci.wafgateway;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;

// WAF filter — the API edge. As a servlet filter it runs before any controller,
// inspecting query, headers, and JSON body. Malicious payloads are blocked 403;
// clean requests flow on to the proxy controller.
@Component
@Order(1)
public class WafFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger("WAF");
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        // 1. Inspect every query-string value.
        for (String[] values : request.getParameterMap().values()) {
            for (String value : values) {
                String hit = WafRules.inspectValue(value);
                if (hit != null) {
                    block(request, response, hit);
                    return;
                }
            }
        }

        // 2. Inspect user-controlled headers.
        String headerHit = WafRules.inspectValue(request.getHeader("X-Forwarded-For"));
        if (headerHit == null) {
            headerHit = WafRules.inspectValue(request.getHeader("Referer"));
        }
        if (headerHit != null) {
            block(request, response, headerHit);
            return;
        }

        // 3. Buffer + inspect the JSON body, then forward a re-readable request.
        byte[] body = request.getInputStream().readAllBytes();
        if (body.length > 0) {
            try {
                Object payload = objectMapper.readValue(body, Object.class);
                String bodyHit = WafRules.inspectPayload(payload);
                if (bodyHit != null) {
                    block(request, response, bodyHit);
                    return;
                }
            } catch (IOException ignored) {
                // Non-JSON body: nothing to inspect against the JSON rule walk.
            }
        }

        chain.doFilter(new CachedBodyRequestWrapper(request, body), response);
    }

    private void block(HttpServletRequest request, HttpServletResponse response, String rule)
            throws IOException {
        log.warn("BLOCKED {} {} rule={}", request.getMethod(), request.getRequestURI(), rule);
        // Uniform 403 contract — never echo the offending payload back.
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setContentType("application/json");
        response.getWriter().write(
                objectMapper.writeValueAsString(Map.of("status", "blocked", "rule", rule)));
    }
}
