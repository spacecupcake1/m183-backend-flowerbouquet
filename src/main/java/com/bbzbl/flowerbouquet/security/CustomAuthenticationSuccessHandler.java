package com.bbzbl.flowerbouquet.security;

import java.io.IOException;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import com.bbzbl.flowerbouquet.user.User;
import com.bbzbl.flowerbouquet.user.UserService;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

/**
 * Custom authentication success handler for secure session management.
 * Handles successful login events with proper session setup and security measures.
 */
@Component
public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    @Autowired
    private UserService userService;

    @Autowired
    private ObjectMapper objectMapper;

    /**
     * Handles successful authentication with secure session management.
     */
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                      Authentication authentication) throws IOException, ServletException {
        
        try {
            // Get user details from authentication
            UserDetailsServiceImpl.CustomUserPrincipal userPrincipal = 
                (UserDetailsServiceImpl.CustomUserPrincipal) authentication.getPrincipal();

            // Get full user details from database
            User user = userService.findByUsername(userPrincipal.getUsername())
                .orElseThrow(() -> new RuntimeException("User not found"));

            // Create new session for security (session fixation protection)
            HttpSession session = request.getSession(true);
            
            // Set session attributes
            session.setAttribute("userId", user.getId());
            session.setAttribute("username", user.getUsername());
            session.setAttribute("isAuthenticated", true);
            session.setAttribute("loginTime", System.currentTimeMillis());
            session.setAttribute("roles", user.getRoles().stream()
                .map(Role::getName)
                .collect(Collectors.toList()));

            // Set session timeout (30 minutes)
            session.setMaxInactiveInterval(30 * 60);

            // Log successful login (for security monitoring)
            logSuccessfulLogin(request, user);

            // Prepare response data
            LoginResponse loginResponse = new LoginResponse();
            loginResponse.setMessage("Login successful");
            loginResponse.setSessionId(session.getId());
            loginResponse.setUserId(user.getId());
            loginResponse.setUsername(user.getUsername());
            loginResponse.setFirstname(user.getFirstname());
            loginResponse.setLastname(user.getLastname());
            loginResponse.setEmail(user.getEmail());
            loginResponse.setRoles(user.getRoles().stream()
                .map(Role::getName)
                .collect(Collectors.toList()));
            loginResponse.setAdmin(userService.isAdmin(user));

            // Set response headers
            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");

            // Security headers
            response.setHeader("X-Content-Type-Options", "nosniff");
            response.setHeader("X-Frame-Options", "DENY");
            response.setHeader("X-XSS-Protection", "1; mode=block");

            // Write response
            response.getWriter().write(objectMapper.writeValueAsString(loginResponse));
            response.getWriter().flush();

        } catch (Exception e) {
            // Log error and send error response
            logLoginError(request, e);
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\":\"Login processing failed\"}");
        }
    }

    /**
     * Logs successful login for security monitoring.
     */
    private void logSuccessfulLogin(HttpServletRequest request, User user) {
        String clientIp = getClientIpAddress(request);
        String userAgent = request.getHeader("User-Agent");
        
        System.out.println(String.format(
            "SECURITY LOG - Successful login: User=%s, IP=%s, UserAgent=%s, Time=%d",
            user.getUsername(), clientIp, userAgent, System.currentTimeMillis()
        ));
        
        // In production, use proper logging framework and consider storing in security audit table
    }

    /**
     * Logs login errors for security monitoring.
     */
    private void logLoginError(HttpServletRequest request, Exception e) {
        String clientIp = getClientIpAddress(request);
        
        System.err.println(String.format(
            "SECURITY LOG - Login processing error: IP=%s, Error=%s, Time=%d",
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
            // Get first IP in case of multiple proxies
            return xForwardedFor.split(",")[0].trim();
        }
        
        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }
        
        return request.getRemoteAddr();
    }

    /**
     * Response DTO for login success.
     */
    public static class LoginResponse {
        private String message;
        private String sessionId;
        private Long userId;
        private String username;
        private String firstname;
        private String lastname;
        private String email;
        private java.util.List<String> roles;
        private boolean isAdmin;

        // Getters and setters
        public String getMessage() { return message; }
        public void setMessage(String message) { this.message = message; }

        public String getSessionId() { return sessionId; }
        public void setSessionId(String sessionId) { this.sessionId = sessionId; }

        public Long getUserId() { return userId; }
        public void setUserId(Long userId) { this.userId = userId; }

        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }

        public String getFirstname() { return firstname; }
        public void setFirstname(String firstname) { this.firstname = firstname; }

        public String getLastname() { return lastname; }
        public void setLastname(String lastname) { this.lastname = lastname; }

        public String getEmail() { return email; }
        public void setEmail(String email) { this.email = email; }

        public java.util.List<String> getRoles() { return roles; }
        public void setRoles(java.util.List<String> roles) { this.roles = roles; }

        public boolean isAdmin() { return isAdmin; }
        public void setAdmin(boolean admin) { isAdmin = admin; }
    }
}