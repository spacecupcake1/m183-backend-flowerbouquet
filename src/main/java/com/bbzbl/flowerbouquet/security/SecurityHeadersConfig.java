package com.bbzbl.flowerbouquet.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.header.HeaderWriter;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Configuration
public class SecurityHeadersConfig {

    /**
     * Content Security Policy header writer bean
     */
    @Bean
    public ContentSecurityPolicyHeaderWriter contentSecurityPolicyHeaderWriter() {
        return new ContentSecurityPolicyHeaderWriter();
    }

    /**
     * Custom Content Security Policy header writer implementation
     */
    public static class ContentSecurityPolicyHeaderWriter implements HeaderWriter {
        
        @Override
        public void writeHeaders(HttpServletRequest request, HttpServletResponse response) {
            // Content Security Policy - restrictive for security
            String cspPolicy = "default-src 'self'; " +
                             "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdnjs.cloudflare.com; " +
                             "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; " +
                             "font-src 'self' https://fonts.gstatic.com data:; " +
                             "img-src 'self' data: https: blob:; " +
                             "connect-src 'self'; " +
                             "frame-ancestors 'none'; " +
                             "base-uri 'self'; " +
                             "form-action 'self'; " +
                             "object-src 'none'; " +
                             "media-src 'self'";
            
            response.setHeader("Content-Security-Policy", cspPolicy);
            
            // Additional security headers for comprehensive protection
            response.setHeader("X-Frame-Options", "DENY");
            response.setHeader("X-Content-Type-Options", "nosniff");
            response.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
            response.setHeader("Permissions-Policy", 
                "geolocation=(), microphone=(), camera=(), payment=(), usb=()");
            
            // Cross-Origin policies
            response.setHeader("Cross-Origin-Embedder-Policy", "require-corp");
            response.setHeader("Cross-Origin-Opener-Policy", "same-origin");
            response.setHeader("Cross-Origin-Resource-Policy", "same-site");
            
            // Remove or mask server information for security
            response.setHeader("Server", "FlowerBouquet/1.0");
            
            // Prevent caching of sensitive content
            if (isSensitiveEndpoint(request)) {
                response.setHeader("Cache-Control", "no-cache, no-store, must-revalidate, private");
                response.setHeader("Pragma", "no-cache");
                response.setHeader("Expires", "0");
            }
        }
        
        /**
         * Determines if the request is for a sensitive endpoint that shouldn't be cached
         */
        private boolean isSensitiveEndpoint(HttpServletRequest request) {
            String uri = request.getRequestURI();
            return uri.contains("/api/users") || 
                   uri.contains("/admin") || 
                   uri.contains("/api/orders") ||
                   uri.contains("/login") ||
                   uri.contains("/logout") ||
                   uri.contains("/register");
        }
    }
}