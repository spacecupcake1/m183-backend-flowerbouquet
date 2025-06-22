package com.bbzbl.flowerbouquet.security;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.http.HttpServletRequest;

@Service
public class EnhancedSecurityAuditService {

    private static final Logger auditLogger = LoggerFactory.getLogger("SECURITY_AUDIT");
    private static final Logger alertLogger = LoggerFactory.getLogger("SECURITY_ALERT");
    
    @Autowired
    private ObjectMapper objectMapper;

    // In-memory tracking for attack patterns (in production, use Redis or database)
    private final Map<String, AtomicInteger> ipFailureCount = new ConcurrentHashMap<>();
    private final Map<String, LocalDateTime> ipLastFailure = new ConcurrentHashMap<>();
    private final Map<String, AtomicInteger> userFailureCount = new ConcurrentHashMap<>();

    // Security thresholds
    private static final int MAX_FAILURES_PER_IP = 5;
    private static final int MAX_FAILURES_PER_USER = 3;
    private static final int ALERT_THRESHOLD_PER_MINUTE = 10;

    /**
     * Log authentication events with enhanced details
     */
    @Async
    public void logAuthenticationEvent(String username, String ipAddress, boolean success, 
                                     String userAgent, String eventType, String details) {
        try {
            // Set MDC for structured logging
            MDC.put("eventType", "AUTHENTICATION");
            MDC.put("username", username);
            MDC.put("ipAddress", ipAddress);
            MDC.put("success", String.valueOf(success));
            MDC.put("timestamp", LocalDateTime.now().toString());

            Map<String, Object> auditEvent = new HashMap<>();
            auditEvent.put("eventType", eventType);
            auditEvent.put("username", username);
            auditEvent.put("ipAddress", ipAddress);
            auditEvent.put("success", success);
            auditEvent.put("userAgent", userAgent);
            auditEvent.put("timestamp", LocalDateTime.now());
            auditEvent.put("details", details);

            if (!success) {
                // Track failed attempts
                trackFailedAttempt(username, ipAddress);
                auditEvent.put("failureCount", getFailureCount(username, ipAddress));
            }

            auditLogger.info("AUTH_EVENT: {}", objectMapper.writeValueAsString(auditEvent));

            // Check for suspicious patterns
            if (!success) {
                checkSuspiciousActivity(username, ipAddress, eventType);
            }

        } catch (Exception e) {
            auditLogger.error("Failed to log authentication event", e);
        } finally {
            MDC.clear();
        }
    }

    /**
     * Log authorization failures with detailed context
     */
    @Async
    public void logAuthorizationEvent(String username, String resource, String action, 
                                    boolean granted, String ipAddress, String reason) {
        try {
            MDC.put("eventType", "AUTHORIZATION");
            MDC.put("username", username);
            MDC.put("resource", resource);
            MDC.put("action", action);

            Map<String, Object> auditEvent = new HashMap<>();
            auditEvent.put("eventType", "AUTHORIZATION");
            auditEvent.put("username", username);
            auditEvent.put("resource", resource);
            auditEvent.put("action", action);
            auditEvent.put("granted", granted);
            auditEvent.put("ipAddress", ipAddress);
            auditEvent.put("reason", reason);
            auditEvent.put("timestamp", LocalDateTime.now());

            if (granted) {
                auditLogger.info("AUTHZ_GRANTED: {}", objectMapper.writeValueAsString(auditEvent));
            } else {
                auditLogger.warn("AUTHZ_DENIED: {}", objectMapper.writeValueAsString(auditEvent));
                
                // Alert on privilege escalation attempts
                if (action.contains("ADMIN") || resource.contains("admin")) {
                    alertLogger.error("PRIVILEGE_ESCALATION_ATTEMPT: {}", 
                                    objectMapper.writeValueAsString(auditEvent));
                }
            }

        } catch (Exception e) {
            auditLogger.error("Failed to log authorization event", e);
        } finally {
            MDC.clear();
        }
    }

    /**
     * Log security violations with threat analysis
     */
    @Async
    public void logSecurityViolation(String username, String violationType, String details, 
                                   String ipAddress, HttpServletRequest request) {
        try {
            MDC.put("eventType", "SECURITY_VIOLATION");
            MDC.put("violationType", violationType);
            MDC.put("username", username != null ? username : "anonymous");

            Map<String, Object> violationEvent = new HashMap<>();
            violationEvent.put("eventType", "SECURITY_VIOLATION");
            violationEvent.put("violationType", violationType);
            violationEvent.put("username", username != null ? username : "anonymous");
            violationEvent.put("ipAddress", ipAddress);
            violationEvent.put("details", details);
            violationEvent.put("timestamp", LocalDateTime.now());
            violationEvent.put("severity", getSeverity(violationType));

            if (request != null) {
                violationEvent.put("userAgent", request.getHeader("User-Agent"));
                violationEvent.put("referer", request.getHeader("Referer"));
                violationEvent.put("requestUri", request.getRequestURI());
                violationEvent.put("method", request.getMethod());
            }

            auditLogger.error("SECURITY_VIOLATION: {}", objectMapper.writeValueAsString(violationEvent));

            // High severity violations trigger immediate alerts
            if ("HIGH".equals(getSeverity(violationType))) {
                alertLogger.error("HIGH_SEVERITY_VIOLATION: {}", 
                                objectMapper.writeValueAsString(violationEvent));
            }

        } catch (Exception e) {
            auditLogger.error("Failed to log security violation", e);
        } finally {
            MDC.clear();
        }
    }

    /**
     * Log data access events for sensitive operations
     */
    @Async
    public void logDataAccessEvent(String username, String entityType, String entityId, 
                                 String operation, boolean success, String ipAddress) {
        try {
            MDC.put("eventType", "DATA_ACCESS");
            MDC.put("username", username);
            MDC.put("entityType", entityType);
            MDC.put("operation", operation);

            Map<String, Object> dataEvent = new HashMap<>();
            dataEvent.put("eventType", "DATA_ACCESS");
            dataEvent.put("username", username);
            dataEvent.put("entityType", entityType);
            dataEvent.put("entityId", entityId);
            dataEvent.put("operation", operation);
            dataEvent.put("success", success);
            dataEvent.put("ipAddress", ipAddress);
            dataEvent.put("timestamp", LocalDateTime.now());

            auditLogger.info("DATA_ACCESS: {}", objectMapper.writeValueAsString(dataEvent));

            // Log sensitive data access
            if (isSensitiveEntity(entityType)) {
                auditLogger.warn("SENSITIVE_DATA_ACCESS: {}", objectMapper.writeValueAsString(dataEvent));
            }

        } catch (Exception e) {
            auditLogger.error("Failed to log data access event", e);
        } finally {
            MDC.clear();
        }
    }

    /**
     * Log session events with security context
     */
    @Async
    public void logSessionEvent(String username, String sessionId, String event, 
                              String ipAddress, String details) {
        try {
            MDC.put("eventType", "SESSION");
            MDC.put("username", username);
            MDC.put("sessionEvent", event);

            Map<String, Object> sessionEvent = new HashMap<>();
            sessionEvent.put("eventType", "SESSION");
            sessionEvent.put("username", username);
            sessionEvent.put("sessionId", sessionId);
            sessionEvent.put("event", event);
            sessionEvent.put("ipAddress", ipAddress);
            sessionEvent.put("details", details);
            sessionEvent.put("timestamp", LocalDateTime.now());

            auditLogger.info("SESSION_EVENT: {}", objectMapper.writeValueAsString(sessionEvent));

        } catch (Exception e) {
            auditLogger.error("Failed to log session event", e);
        } finally {
            MDC.clear();
        }
    }

    /**
     * Track failed authentication attempts
     */
    private void trackFailedAttempt(String username, String ipAddress) {
        // Track by IP
        ipFailureCount.computeIfAbsent(ipAddress, k -> new AtomicInteger(0)).incrementAndGet();
        ipLastFailure.put(ipAddress, LocalDateTime.now());

        // Track by username
        if (username != null) {
            userFailureCount.computeIfAbsent(username, k -> new AtomicInteger(0)).incrementAndGet();
        }
    }

    /**
     * Get failure count for user/IP combination
     */
    private Map<String, Integer> getFailureCount(String username, String ipAddress) {
        Map<String, Integer> counts = new HashMap<>();
        counts.put("ipFailures", ipFailureCount.getOrDefault(ipAddress, new AtomicInteger(0)).get());
        counts.put("userFailures", username != null ? 
                  userFailureCount.getOrDefault(username, new AtomicInteger(0)).get() : 0);
        return counts;
    }

    /**
     * Check for suspicious activity patterns
     */
    private void checkSuspiciousActivity(String username, String ipAddress, String eventType) {
        int ipFailures = ipFailureCount.getOrDefault(ipAddress, new AtomicInteger(0)).get();
        int userFailures = username != null ? 
                          userFailureCount.getOrDefault(username, new AtomicInteger(0)).get() : 0;

        // Alert on excessive failures
        if (ipFailures >= MAX_FAILURES_PER_IP) {
            alertLogger.error("SUSPICIOUS_IP_ACTIVITY: IP {} has {} failed attempts", ipAddress, ipFailures);
        }

        if (userFailures >= MAX_FAILURES_PER_USER) {
            alertLogger.error("SUSPICIOUS_USER_ACTIVITY: User {} has {} failed attempts", username, userFailures);
        }

        // Alert on rapid-fire attempts
        LocalDateTime lastFailure = ipLastFailure.get(ipAddress);
        if (lastFailure != null && lastFailure.isAfter(LocalDateTime.now().minusMinutes(1))) {
            alertLogger.error("RAPID_FAILURE_ATTEMPTS: IP {} attempting rapid authentication", ipAddress);
        }
    }

    /**
     * Get severity level for violation types
     */
    private String getSeverity(String violationType) {
        switch (violationType.toUpperCase()) {
            case "SQL_INJECTION":
            case "XSS_ATTEMPT":
            case "PATH_TRAVERSAL":
            case "PRIVILEGE_ESCALATION":
                return "HIGH";
            case "INVALID_INPUT":
            case "RATE_LIMIT_EXCEEDED":
                return "MEDIUM";
            default:
                return "LOW";
        }
    }

    /**
     * Check if entity type contains sensitive data
     */
    private boolean isSensitiveEntity(String entityType) {
        return entityType.toLowerCase().contains("user") ||
               entityType.toLowerCase().contains("password") ||
               entityType.toLowerCase().contains("payment") ||
               entityType.toLowerCase().contains("order");
    }

    /**
     * Clear failure counts (call on successful authentication)
     */
    public void clearFailureCount(String username, String ipAddress) {
        if (ipAddress != null) {
            ipFailureCount.remove(ipAddress);
            ipLastFailure.remove(ipAddress);
        }
        if (username != null) {
            userFailureCount.remove(username);
        }
    }
}