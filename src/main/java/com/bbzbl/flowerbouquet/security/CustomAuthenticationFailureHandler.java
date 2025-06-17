package com.bbzbl.flowerbouquet.security;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Custom authentication failure handler for secure error handling and brute force protection.
 * Handles failed login attempts with security logging and rate limiting.
 */
@Component
public class CustomAuthenticationFailureHandler implements AuthenticationFailureHandler {

    @Autowired
    private ObjectMapper objectMapper;

    // Simple in-memory rate limiting (in production, use Redis or database)
    private final Map<String, AtomicInteger> attemptCounts = new ConcurrentHashMap<>();
    private final Map<String, Long> lastAttemptTimes = new ConcurrentHashMap<>();
    
    private static final int MAX_ATTEMPTS = 5;
    private static final long LOCKOUT_DURATION = 15 * 60 * 1000; // 15 minutes
    private static final long ATTEMPT_RESET_TIME = 60 * 60 * 1000; // 1 hour
    private static final int HTTP_TOO_MANY_REQUESTS = 429; // Define our own constant

    /**
     * Handles authentication failure with security measures and logging.
     */
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                      AuthenticationException exception) throws IOException, ServletException {
        
        String clientIp = getClientIpAddress(request);
        String username = request.getParameter("username");
        
        try {
            // Check and update rate limiting
            boolean isLocked = checkAndUpdateRateLimit(clientIp);
            
            // Log failed attempt
            logFailedAttempt(request, username, exception, isLocked);
            
            // Prepare error response
            Map<String, Object> errorResponse = new HashMap<>();
            
            if (isLocked) {
                errorResponse.put("message", "Too many failed attempts. Please try again later.");
                errorResponse.put("lockoutDuration", LOCKOUT_DURATION / 1000 / 60); // minutes
                response.setStatus(HTTP_TOO_MANY_REQUESTS); // 429
            } else {
                String errorMessage = getErrorMessage(exception);
                errorResponse.put("message", errorMessage);
                
                // Include remaining attempts info (but don't reveal exact count for security)
                int attempts = attemptCounts.getOrDefault(clientIp, new AtomicInteger(0)).get();
                if (attempts >= 3) {
                    errorResponse.put("warning", "Multiple failed attempts detected.");
                }
                
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED); // 401
            }
            
            // Set response headers
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
            
            // Security headers
            response.setHeader("X-Content-Type-Options", "nosniff");
            response.setHeader("X-Frame-Options", "DENY");
            response.setHeader("X-XSS-Protection", "1; mode=block");
            
            // Write response
            response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
            response.getWriter().flush();
            
        } catch (Exception e) {
            // Log error and send generic error response
            logProcessingError(request, e);
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\":\"Authentication processing failed\"}");
        }
    }

    /**
     * Checks and updates rate limiting for IP address.
     * Returns true if the IP is currently locked out.
     */
    private boolean checkAndUpdateRateLimit(String clientIp) {
        long currentTime = System.currentTimeMillis();
        
        // Check if IP is currently locked out
        Long lastAttemptTime = lastAttemptTimes.get(clientIp);
        if (lastAttemptTime != null) {
            long timeSinceLastAttempt = currentTime - lastAttemptTime;
            
            // Reset counter if enough time has passed
            if (timeSinceLastAttempt > ATTEMPT_RESET_TIME) {
                attemptCounts.remove(clientIp);
                lastAttemptTimes.remove(clientIp);
            } else {
                // Check if still in lockout period
                AtomicInteger attempts = attemptCounts.get(clientIp);
                if (attempts != null && attempts.get() >= MAX_ATTEMPTS) {
                    if (timeSinceLastAttempt < LOCKOUT_DURATION) {
                        return true; // Still locked out
                    } else {
                        // Lockout period expired, reset counter
                        attemptCounts.remove(clientIp);
                        lastAttemptTimes.remove(clientIp);
                    }
                }
            }
        }
        
        // Increment attempt count
        attemptCounts.computeIfAbsent(clientIp, k -> new AtomicInteger(0)).incrementAndGet();
        lastAttemptTimes.put(clientIp, currentTime);
        
        // Check if just reached max attempts
        return attemptCounts.get(clientIp).get() >= MAX_ATTEMPTS;
    }

    /**
     * Gets user-friendly error message based on exception type.
     */
    private String getErrorMessage(AuthenticationException exception) {
        if (exception instanceof BadCredentialsException) {
            return "Invalid username or password";
        } else if (exception instanceof UsernameNotFoundException) {
            return "Invalid username or password"; // Don't reveal if username exists
        } else if (exception instanceof DisabledException) {
            return "Account is disabled";
        } else if (exception instanceof LockedException) {
            return "Account is locked";
        } else {
            return "Authentication failed";
        }
    }

    /**
     * Logs failed authentication attempt for security monitoring.
     */
    private void logFailedAttempt(HttpServletRequest request, String username, 
                                AuthenticationException exception, boolean isLocked) {
        String clientIp = getClientIpAddress(request);
        String userAgent = request.getHeader("User-Agent");
        int attempts = attemptCounts.getOrDefault(clientIp, new AtomicInteger(0)).get();
        
        System.out.println(String.format(
            "SECURITY LOG - Failed login: Username=%s, IP=%s, UserAgent=%s, Attempts=%d, Locked=%s, Exception=%s, Time=%d",
            sanitizeForLog(username), clientIp, sanitizeForLog(userAgent), 
            attempts, isLocked, exception.getClass().getSimpleName(), System.currentTimeMillis()
        ));
        
        // In production:
        // 1. Use proper logging framework (SLF4J + Logback)
        // 2. Store in security audit table
        // 3. Set up alerts for multiple failed attempts
        // 4. Consider integrating with SIEM systems
    }

    /**
     * Logs processing errors for debugging.
     */
    private void logProcessingError(HttpServletRequest request, Exception e) {
        String clientIp = getClientIpAddress(request);
        
        System.err.println(String.format(
            "SECURITY LOG - Authentication processing error: IP=%s, Error=%s, Time=%d",
            clientIp, e.getMessage(), System.currentTimeMillis()
        ));
        
        // In production, use proper logging framework
    }

    /**
     * Gets client IP address from request, handling proxy headers.
     */
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

    /**
     * Sanitizes input for safe logging (prevents log injection).
     */
    private String sanitizeForLog(String input) {
        if (input == null) return "null";
        
        // Remove line breaks and control characters to prevent log injection
        return input.replaceAll("[\r\n\t]", "_")
                   .replaceAll("[\\p{Cntrl}]", "")
                   .substring(0, Math.min(input.length(), 100)); // Limit length
    }

    /**
     * Gets current attempt count for an IP (for testing/monitoring).
     */
    public int getAttemptCount(String clientIp) {
        AtomicInteger attempts = attemptCounts.get(clientIp);
        return attempts != null ? attempts.get() : 0;
    }

    /**
     * Manually reset attempt count for an IP (for admin functionality).
     */
    public void resetAttemptCount(String clientIp) {
        attemptCounts.remove(clientIp);
        lastAttemptTimes.remove(clientIp);
    }

    /**
     * Check if IP is currently locked out.
     */
    public boolean isIpLocked(String clientIp) {
        Long lastAttemptTime = lastAttemptTimes.get(clientIp);
        if (lastAttemptTime == null) return false;
        
        AtomicInteger attempts = attemptCounts.get(clientIp);
        if (attempts == null || attempts.get() < MAX_ATTEMPTS) return false;
        
        long timeSinceLastAttempt = System.currentTimeMillis() - lastAttemptTime;
        return timeSinceLastAttempt < LOCKOUT_DURATION;
    }
}