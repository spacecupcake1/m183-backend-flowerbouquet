package com.bbzbl.flowerbouquet.security;

import java.time.Instant;

/**
 * Session information storage class
 */
public class SessionInfo {
    private String sessionId;
    private Instant creationTime;
    private Instant lastAccessTime;
    private int maxInactiveInterval;
    private String username;

    // Constructors
    public SessionInfo() {}

    public SessionInfo(String sessionId) {
        this.sessionId = sessionId;
    }

    // Getters and Setters
    public String getSessionId() {
        return sessionId;
    }

    public void setSessionId(String sessionId) {
        this.sessionId = sessionId;
    }

    public Instant getCreationTime() {
        return creationTime;
    }

    public void setCreationTime(Instant creationTime) {
        this.creationTime = creationTime;
    }

    public Instant getLastAccessTime() {
        return lastAccessTime;
    }

    public void setLastAccessTime(Instant lastAccessTime) {
        this.lastAccessTime = lastAccessTime;
    }

    public int getMaxInactiveInterval() {
        return maxInactiveInterval;
    }

    public void setMaxInactiveInterval(int maxInactiveInterval) {
        this.maxInactiveInterval = maxInactiveInterval;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    @Override
    public String toString() {
        return "SessionInfo{" +
                "sessionId='" + sessionId + '\'' +
                ", creationTime=" + creationTime +
                ", lastAccessTime=" + lastAccessTime +
                ", maxInactiveInterval=" + maxInactiveInterval +
                ", username='" + username + '\'' +
                '}';
    }
}