package com.bbzbl.flowerbouquet.security;

import java.time.LocalDateTime;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Service for comprehensive security event logging and auditing
 */
@Service
public class SecurityAuditService {

    private static final Logger auditLogger = LoggerFactory.getLogger("AUDIT");
    private static final Logger securityLogger = LoggerFactory.getLogger("SECURITY");

    /**
     * Log user login attempts
     */
    public void logUserLogin(String username, String ipAddress, boolean success, String reason) {
        String status = success ? "SUCCESS" : "FAILURE";
        String message = String.format("LOGIN_%s | User: %s | IP: %s | Time: %s", 
                                     status, username, ipAddress, LocalDateTime.now());
        
        if (!success && reason != null) {
            message += " | Reason: " + reason;
        }
        
        if (success) {
            auditLogger.info(message);
        } else {
            securityLogger.warn(message);
        }
    }

    /**
     * Log user logout events
     */
    public void logUserLogout(String username, String ipAddress, boolean success, String reason) {
        String status = success ? "SUCCESS" : "FAILURE";
        String message = String.format("LOGOUT_%s | User: %s | IP: %s | Time: %s", 
                                     status, username, ipAddress, LocalDateTime.now());
        
        if (!success && reason != null) {
            message += " | Reason: " + reason;
        }
        
        auditLogger.info(message);
    }

    /**
     * Log user registration events
     */
    public void logUserRegistration(String username, String ipAddress, boolean success, String reason) {
        String status = success ? "SUCCESS" : "FAILURE";
        String message = String.format("REGISTRATION_%s | User: %s | IP: %s | Time: %s", 
                                     status, username, ipAddress, LocalDateTime.now());
        
        if (!success && reason != null) {
            message += " | Reason: " + reason;
        }
        
        if (success) {
            auditLogger.info(message);
        } else {
            securityLogger.warn(message);
        }
    }

    /**
     * Log admin actions on flowers
     */
    public void logFlowerAction(String username, String action, String flowerName, String ipAddress, boolean success, String reason) {
        String status = success ? "SUCCESS" : "FAILURE";
        String message = String.format("FLOWER_%s_%s | User: %s | Flower: %s | IP: %s | Time: %s", 
                                     action.toUpperCase(), status, username, flowerName, ipAddress, LocalDateTime.now());
        
        if (!success && reason != null) {
            message += " | Reason: " + reason;
        }
        
        auditLogger.info(message);
    }

    /**
     * Log authorization failures
     */
    public void logAuthorizationFailure(String username, String resource, String action, String ipAddress) {
        String message = String.format("AUTHORIZATION_FAILURE | User: %s | Resource: %s | Action: %s | IP: %s | Time: %s", 
                                     username, resource, action, ipAddress, LocalDateTime.now());
        
        securityLogger.warn(message);
    }

    /**
     * Log security violations (XSS, SQL injection attempts, etc.)
     */
    public void logSecurityViolation(String username, String violationType, String details, String ipAddress) {
        String message = String.format("SECURITY_VIOLATION | User: %s | Type: %s | Details: %s | IP: %s | Time: %s", 
                                     username != null ? username : "anonymous", 
                                     violationType, details, ipAddress, LocalDateTime.now());
        
        securityLogger.error(message);
    }

    /**
     * Log rate limiting events
     */
    public void logRateLimitEvent(String ipAddress, String endpoint, int attemptCount) {
        String message = String.format("RATE_LIMIT_TRIGGERED | IP: %s | Endpoint: %s | Attempts: %d | Time: %s", 
                                     ipAddress, endpoint, attemptCount, LocalDateTime.now());
        
        securityLogger.warn(message);
    }

    /**
     * Log session events
     */
    public void logSessionEvent(String username, String event, String sessionId, String ipAddress) {
        String message = String.format("SESSION_%s | User: %s | SessionID: %s | IP: %s | Time: %s", 
                                     event.toUpperCase(), username, sessionId, ipAddress, LocalDateTime.now());
        
        auditLogger.info(message);
    }
}