package com.bbzbl.flowerbouquet.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Scheduled tasks for security maintenance and cleanup
 */
@Component
public class SecurityMaintenanceScheduler {

    private static final Logger logger = LoggerFactory.getLogger(SecurityMaintenanceScheduler.class);

    @Autowired
    private RateLimitingService rateLimitingService;

    /**
     * Cleanup expired rate limiting entries every hour
     */
    @Scheduled(fixedRate = 3600000) // Every hour
    public void cleanupRateLimitData() {
        try {
            rateLimitingService.cleanup();
            logger.debug("Rate limiting cleanup completed successfully");
        } catch (Exception e) {
            logger.error("Error during rate limiting cleanup: {}", e.getMessage());
        }
    }

    /**
     * Log security statistics every 6 hours
     */
    @Scheduled(fixedRate = 21600000) // Every 6 hours
    public void logSecurityStatistics() {
        try {
            // This would implement security metrics logging
            logger.info("Security maintenance check completed");
        } catch (Exception e) {
            logger.error("Error during security statistics logging: {}", e.getMessage());
        }
    }
}