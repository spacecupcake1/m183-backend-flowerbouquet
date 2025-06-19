package com.bbzbl.flowerbouquet.security;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.security.web.session.HttpSessionCreatedEvent;
import org.springframework.security.web.session.HttpSessionDestroyedEvent;
import org.springframework.stereotype.Service;

import jakarta.servlet.http.HttpSession;

@Service
public class SessionManagementService {
    
    private static final Logger logger = LoggerFactory.getLogger(SessionManagementService.class);
    
    private final Map<String, SessionInfo> activeSessions = new ConcurrentHashMap<>();
    
    @EventListener
    public void onSessionCreated(HttpSessionCreatedEvent event) {
        HttpSession session = event.getSession();
        
        SessionInfo sessionInfo = new SessionInfo();
        sessionInfo.setSessionId(session.getId());
        sessionInfo.setCreationTime(Instant.ofEpochMilli(session.getCreationTime()));
        sessionInfo.setLastAccessTime(Instant.ofEpochMilli(session.getLastAccessedTime()));
        sessionInfo.setMaxInactiveInterval(session.getMaxInactiveInterval());
        
        activeSessions.put(session.getId(), sessionInfo);
        
        logger.info("Session created: {}", session.getId());
    }
    
    @EventListener
    public void onSessionDestroyed(HttpSessionDestroyedEvent event) {
        String sessionId = event.getSession().getId();
        activeSessions.remove(sessionId);
        
        logger.info("Session destroyed: {}", sessionId);
    }
    
    /**
     * Get active session count
     */
    public int getActiveSessionCount() {
        return activeSessions.size();
    }
    
    /**
     * Get session info by session ID
     */
    public SessionInfo getSessionInfo(String sessionId) {
        return activeSessions.get(sessionId);
    }
    
    /**
     * Invalidate all sessions for a user (useful for security events)
     */
    public void invalidateUserSessions(String username) {
        // Implementation depends on your session store
        // This is a simplified version
        activeSessions.entrySet().removeIf(entry -> {
            // Check if session belongs to user
            return isUserSession(entry.getKey(), username);
        });
    }
    
    private boolean isUserSession(String sessionId, String username) {
        SessionInfo sessionInfo = activeSessions.get(sessionId);
        return sessionInfo != null && username.equals(sessionInfo.getUsername());
    }
}