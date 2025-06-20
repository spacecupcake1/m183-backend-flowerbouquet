package com.bbzbl.flowerbouquet.security;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.springframework.stereotype.Service;

/**
 * Service for implementing rate limiting to prevent brute force attacks
 */
@Service
public class RateLimitingService {

    // Track failed login attempts by IP address
    private final ConcurrentMap<String, AttemptInfo> failedAttempts = new ConcurrentHashMap<>();
    
    // Configuration
    private static final int MAX_ATTEMPTS = 5;
    private static final int LOCKOUT_DURATION_MINUTES = 15;
    private static final int ATTEMPT_WINDOW_MINUTES = 5;

    /**
     * Check if IP is currently rate limited
     */
    public boolean isRateLimited(String ipAddress) {
        AttemptInfo info = failedAttempts.get(ipAddress);
        
        if (info == null) {
            return false;
        }
        
        // Check if lockout period has expired
        if (info.lockedUntil != null && LocalDateTime.now().isAfter(info.lockedUntil)) {
            failedAttempts.remove(ipAddress);
            return false;
        }
        
        return info.lockedUntil != null;
    }

    /**
     * Record a failed login attempt
     */
    public void recordFailedAttempt(String ipAddress) {
        AttemptInfo info = failedAttempts.computeIfAbsent(ipAddress, k -> new AttemptInfo());
        
        LocalDateTime now = LocalDateTime.now();
        
        // Reset count if outside attempt window
        if (info.firstAttempt == null || 
            ChronoUnit.MINUTES.between(info.firstAttempt, now) > ATTEMPT_WINDOW_MINUTES) {
            info.firstAttempt = now;
            info.attemptCount = 1;
            info.lockedUntil = null;
        } else {
            info.attemptCount++;
        }
        
        info.lastAttempt = now;
        
        // Lock if too many attempts
        if (info.attemptCount >= MAX_ATTEMPTS) {
            info.lockedUntil = now.plusMinutes(LOCKOUT_DURATION_MINUTES);
        }
    }

    /**
     * Clear failed attempts for IP (e.g., on successful login)
     */
    public void clearFailedAttempts(String ipAddress) {
        failedAttempts.remove(ipAddress);
    }

    /**
     * Get remaining lockout time in minutes
     */
    public long getRemainingLockoutMinutes(String ipAddress) {
        AttemptInfo info = failedAttempts.get(ipAddress);
        
        if (info == null || info.lockedUntil == null) {
            return 0;
        }
        
        long remaining = ChronoUnit.MINUTES.between(LocalDateTime.now(), info.lockedUntil);
        return Math.max(0, remaining);
    }

    /**
     * Get attempt count for IP
     */
    public int getAttemptCount(String ipAddress) {
        AttemptInfo info = failedAttempts.get(ipAddress);
        return info != null ? info.attemptCount : 0;
    }

    /**
     * Clean up old entries (call periodically)
     */
    public void cleanup() {
        LocalDateTime cutoff = LocalDateTime.now().minusHours(1);
        failedAttempts.entrySet().removeIf(entry -> {
            AttemptInfo info = entry.getValue();
            return info.lastAttempt.isBefore(cutoff) && 
                   (info.lockedUntil == null || info.lockedUntil.isBefore(LocalDateTime.now()));
        });
    }

    private static class AttemptInfo {
        LocalDateTime firstAttempt;
        LocalDateTime lastAttempt;
        LocalDateTime lockedUntil;
        int attemptCount = 0;
    }
}