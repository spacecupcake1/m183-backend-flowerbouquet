package com.bbzbl.flowerbouquet.security;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Configuration properties for security settings
 */
@Component
@ConfigurationProperties(prefix = "app.security")
public class SecurityProperties {

    private String pepper = "MySecretPepperKey2024!@#$%^&*()";
    private RateLimit rateLimit = new RateLimit();
    private Session session = new Session();

    public static class RateLimit {
        private int maxAttempts = 5;
        private int lockoutDuration = 900; // 15 minutes in seconds
        private int attemptWindow = 300; // 5 minutes in seconds

        // Getters and setters
        public int getMaxAttempts() { return maxAttempts; }
        public void setMaxAttempts(int maxAttempts) { this.maxAttempts = maxAttempts; }

        public int getLockoutDuration() { return lockoutDuration; }
        public void setLockoutDuration(int lockoutDuration) { this.lockoutDuration = lockoutDuration; }

        public int getAttemptWindow() { return attemptWindow; }
        public void setAttemptWindow(int attemptWindow) { this.attemptWindow = attemptWindow; }
    }

    public static class Session {
        private int timeout = 3600; // 1 hour in seconds
        private int maxSessions = 3;
        private boolean requireHttps = false;

        // Getters and setters
        public int getTimeout() { return timeout; }
        public void setTimeout(int timeout) { this.timeout = timeout; }

        public int getMaxSessions() { return maxSessions; }
        public void setMaxSessions(int maxSessions) { this.maxSessions = maxSessions; }

        public boolean isRequireHttps() { return requireHttps; }
        public void setRequireHttps(boolean requireHttps) { this.requireHttps = requireHttps; }
    }

    // Main getters and setters
    public String getPepper() { return pepper; }
    public void setPepper(String pepper) { this.pepper = pepper; }

    public RateLimit getRateLimit() { return rateLimit; }
    public void setRateLimit(RateLimit rateLimit) { this.rateLimit = rateLimit; }

    public Session getSession() { return session; }
    public void setSession(Session session) { this.session = session; }
}