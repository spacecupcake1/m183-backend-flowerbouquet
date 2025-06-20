package com.bbzbl.flowerbouquet.security;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Custom security filter for rate limiting and additional security checks
 */
@Component
public class SecurityFilter extends OncePerRequestFilter {

    @Autowired
    private RateLimitingService rateLimitingService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        String ipAddress = getClientIpAddress(request);
        String requestURI = request.getRequestURI();
        
        // Apply rate limiting to authentication endpoints
        if (requestURI.equals("/api/users/login") || requestURI.equals("/api/users/register")) {
            if (rateLimitingService.isRateLimited(ipAddress)) {
                long remainingMinutes = rateLimitingService.getRemainingLockoutMinutes(ipAddress);
                
                response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
                response.setContentType("application/json");
                response.getWriter().write(String.format(
                    "{\"error\":\"Too many attempts. Please try again in %d minutes.\"}", 
                    remainingMinutes
                ));
                return;
            }
        }
        
        // Add security headers
        addSecurityHeaders(response);
        
        // Continue with the filter chain
        filterChain.doFilter(request, response);
    }

    private void addSecurityHeaders(HttpServletResponse response) {
        // Remove server information
        response.setHeader("Server", "");
        
        // Add security headers if not already present
        if (response.getHeader("X-Content-Type-Options") == null) {
            response.setHeader("X-Content-Type-Options", "nosniff");
        }
        
        if (response.getHeader("X-Frame-Options") == null) {
            response.setHeader("X-Frame-Options", "DENY");
        }
        
        if (response.getHeader("X-XSS-Protection") == null) {
            response.setHeader("X-XSS-Protection", "1; mode=block");
        }
    }

    private String getClientIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        
        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }
        
        return request.getRemoteAddr();
    }
}