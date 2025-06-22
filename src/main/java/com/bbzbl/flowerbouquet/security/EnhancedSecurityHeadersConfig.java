package com.bbzbl.flowerbouquet.security;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
@Order(1)
public class EnhancedSecurityHeadersConfig extends OncePerRequestFilter {

    @Value("${app.security.csp.enabled:true}")
    private boolean cspEnabled;

    @Value("${app.security.environment:development}")
    private String environment;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        addSecurityHeaders(request, response);
        filterChain.doFilter(request, response);
    }

    private void addSecurityHeaders(HttpServletRequest request, HttpServletResponse response) {
        
        // 1. Content Security Policy (CSP) - Critical for XSS Prevention
        if (cspEnabled) {
            String csp = buildContentSecurityPolicy();
            response.setHeader("Content-Security-Policy", csp);
            response.setHeader("Content-Security-Policy-Report-Only", csp); // For testing
        }

        // 2. X-Content-Type-Options - Prevent MIME type sniffing
        response.setHeader("X-Content-Type-Options", "nosniff");

        // 3. X-Frame-Options - Prevent clickjacking
        response.setHeader("X-Frame-Options", "DENY");

        // 4. X-XSS-Protection - Enable XSS filtering (legacy but still useful)
        response.setHeader("X-XSS-Protection", "1; mode=block");

        // 5. Strict-Transport-Security - Enforce HTTPS (only add if HTTPS)
        if (request.isSecure() || "production".equals(environment)) {
            response.setHeader("Strict-Transport-Security", 
                             "max-age=31536000; includeSubDomains; preload");
        }

        // 6. Referrer Policy - Control referrer information
        response.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");

        // 7. Permissions Policy - Control browser features
        response.setHeader("Permissions-Policy", 
                         "camera=(), microphone=(), geolocation=(), payment=()");

        // 8. Cross-Origin Policies
        response.setHeader("Cross-Origin-Opener-Policy", "same-origin");
        response.setHeader("Cross-Origin-Resource-Policy", "same-site");
        response.setHeader("Cross-Origin-Embedder-Policy", "require-corp");

        // 9. Cache Control for sensitive endpoints
        if (isSensitiveEndpoint(request)) {
            response.setHeader("Cache-Control", 
                             "no-cache, no-store, must-revalidate, private");
            response.setHeader("Pragma", "no-cache");
            response.setHeader("Expires", "0");
        }

        // 10. Server Information Hiding
        response.setHeader("Server", "FlowerBouquet/1.0");

        // 11. Custom Security Headers
        response.setHeader("X-Permitted-Cross-Domain-Policies", "none");
        response.setHeader("X-Download-Options", "noopen");
    }

    private String buildContentSecurityPolicy() {
        StringBuilder csp = new StringBuilder();
        
        // Default source - only self
        csp.append("default-src 'self'; ");
        
        // Script sources - be very restrictive
        csp.append("script-src 'self' 'unsafe-eval' 'unsafe-inline' ")
           .append("https://cdnjs.cloudflare.com ")
           .append("https://cdn.jsdelivr.net; ");
        
        // Style sources
        csp.append("style-src 'self' 'unsafe-inline' ")
           .append("https://fonts.googleapis.com ")
           .append("https://cdnjs.cloudflare.com; ");
        
        // Font sources
        csp.append("font-src 'self' ")
           .append("https://fonts.gstatic.com ")
           .append("data:; ");
        
        // Image sources
        csp.append("img-src 'self' data: blob: ")
           .append("https: http:; "); // Allow images from HTTPS/HTTP for flexibility
        
        // Connect sources (AJAX, WebSocket, etc.)
        if ("development".equals(environment)) {
            csp.append("connect-src 'self' ")
               .append("http://localhost:* ")
               .append("https://localhost:* ")
               .append("ws://localhost:* ")
               .append("wss://localhost:*; ");
        } else {
            csp.append("connect-src 'self'; ");
        }
        
        // Media sources
        csp.append("media-src 'self'; ");
        
        // Object sources - block plugins
        csp.append("object-src 'none'; ");
        
        // Frame sources - control embedding
        csp.append("frame-src 'none'; ");
        
        // Worker sources
        csp.append("worker-src 'self'; ");
        
        // Base URI restriction
        csp.append("base-uri 'self'; ");
        
        // Form action restriction
        csp.append("form-action 'self'; ");
        
        // Frame ancestors - prevent embedding
        csp.append("frame-ancestors 'none'; ");
        
        // Upgrade insecure requests in production
        if ("production".equals(environment)) {
            csp.append("upgrade-insecure-requests; ");
        }

        return csp.toString();
    }

    private boolean isSensitiveEndpoint(HttpServletRequest request) {
        String uri = request.getRequestURI();
        return uri.contains("/api/users") || 
               uri.contains("/api/admin") || 
               uri.contains("/login") ||
               uri.contains("/logout") ||
               uri.contains("/register") ||
               uri.contains("/api/orders") ||
               uri.contains("/h2-console");
    }
}