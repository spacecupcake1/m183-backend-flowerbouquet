package com.bbzbl.flowerbouquet.security;

import java.security.Principal;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.bbzbl.flowerbouquet.security.UserDetailsServiceImpl.CustomUserPrincipal;
import com.bbzbl.flowerbouquet.user.User;
import com.bbzbl.flowerbouquet.user.UserRegistrationDTO;
import com.bbzbl.flowerbouquet.user.UserService;
import com.bbzbl.flowerbouquet.validation.NoSqlInjection;
import com.bbzbl.flowerbouquet.validation.NoXSS;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;

/**
 * Enhanced REST Controller for handling authentication operations with comprehensive security.
 */
@RestController
@RequestMapping("/api/users")
@CrossOrigin(origins = "http://localhost:4200", allowCredentials = "true")
@Validated
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);
    private static final Logger securityLogger = LoggerFactory.getLogger("SECURITY");

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserService userService;

    @Autowired
    private InputValidationService inputValidationService;

    @Autowired
    private RateLimitingService rateLimitingService;

    @Autowired
    private SecurityAuditService securityAuditService;

    /**
     * Enhanced login endpoint with comprehensive security checks.
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest loginRequest, 
                                HttpServletRequest request) {
        
        String ipAddress = getClientIpAddress(request);
        
        try {
            // Debug logging
            logger.info("Login attempt - Username: {}, IP: {}", loginRequest.getUsername(), ipAddress);
            
            // Check rate limiting first
            if (rateLimitingService.isRateLimited(ipAddress)) {
                long remainingMinutes = rateLimitingService.getRemainingLockoutMinutes(ipAddress);
                
                securityLogger.warn("Rate-limited login attempt from IP {}: {} attempts, {} minutes remaining", 
                                   ipAddress, rateLimitingService.getAttemptCount(ipAddress), remainingMinutes);
                
                return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(Map.of(
                    "error", "Too many failed attempts",
                    "message", String.format("Please try again in %d minutes", remainingMinutes),
                    "remainingMinutes", remainingMinutes
                ));
            }

            // Input validation
            inputValidationService.validateInput(loginRequest.getUsername(), "username");
            inputValidationService.validateInput(loginRequest.getPassword(), "password");

            // Log login attempt
            securityLogger.info("Login attempt for user '{}' from IP: {}", 
                               loginRequest.getUsername(), ipAddress);

            // Authenticate user
            Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                    loginRequest.getUsername().trim(), 
                    loginRequest.getPassword()
                )
            );

            // Clear failed attempts on successful authentication
            rateLimitingService.clearFailedAttempts(ipAddress);

            // Create secure session
            SecurityContextHolder.getContext().setAuthentication(authentication);

            // Get user details
            CustomUserPrincipal userPrincipal = (CustomUserPrincipal) authentication.getPrincipal();

            // Create session and set attributes
            HttpSession session = request.getSession(true);
            session.setAttribute("SPRING_SECURITY_CONTEXT", SecurityContextHolder.getContext());
            session.setMaxInactiveInterval(3600); // 1 hour

            // Create response
            Map<String, Object> response = new HashMap<>();
            response.put("message", "Login successful");
            response.put("sessionId", session.getId());
            response.put("userId", userPrincipal.getId());
            response.put("username", userPrincipal.getUsername());
            response.put("firstname", userPrincipal.getFirstname());
            response.put("lastname", userPrincipal.getLastname());
            response.put("email", userPrincipal.getEmail());
            response.put("roles", userPrincipal.getAuthorities().stream()
                .map(authority -> authority.getAuthority())
                .collect(Collectors.toList()));
            response.put("isAdmin", userPrincipal.isAdmin());

            // Log successful authentication
            securityLogger.info("User '{}' logged in successfully from IP: {}", 
                               userPrincipal.getUsername(), ipAddress);

            securityAuditService.logUserLogin(
                userPrincipal.getUsername(), ipAddress, true, "Login successful");

            return ResponseEntity.ok(response);

        } catch (BadCredentialsException e) {
            // Record failed attempt
            rateLimitingService.recordFailedAttempt(ipAddress);
            
            securityLogger.warn("Failed login for user '{}' from IP: {}, attempts: {}", 
                               loginRequest.getUsername(), ipAddress, 
                               rateLimitingService.getAttemptCount(ipAddress));
            
            securityAuditService.logUserLogin(
                loginRequest.getUsername(), ipAddress, false, "Invalid credentials");

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of(
                "error", "Invalid username or password",
                "attemptsRemaining", Math.max(0, 5 - rateLimitingService.getAttemptCount(ipAddress))
            ));

        } catch (LockedException e) {
            securityLogger.warn("Login attempt for locked user '{}' from IP: {}", 
                               loginRequest.getUsername(), ipAddress);
            
            securityAuditService.logUserLogin(
                loginRequest.getUsername(), ipAddress, false, "Account locked");

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of(
                "error", "Account is locked"
            ));

        } catch (DisabledException e) {
            securityLogger.warn("Login attempt for disabled user '{}' from IP: {}", 
                               loginRequest.getUsername(), ipAddress);
            
            securityAuditService.logUserLogin(
                loginRequest.getUsername(), ipAddress, false, "Account disabled");

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of(
                "error", "Account is disabled"
            ));

        } catch (Exception e) {
            logger.error("Login error for user '{}' from IP {}: {}", 
                        loginRequest.getUsername(), ipAddress, e.getMessage(), e);
            
            securityAuditService.logUserLogin(
                loginRequest.getUsername(), ipAddress, false, "System error: " + e.getMessage());

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of(
                "error", "Login failed"
            ));
        }
    }

    /**
     * Enhanced logout endpoint with comprehensive session cleanup and logging.
     */
    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request, Principal principal) {
        
        String ipAddress = getClientIpAddress(request);
        String username = principal != null ? principal.getName() : "unknown";

        try {
            // Invalidate session
            HttpSession session = request.getSession(false);
            if (session != null) {
                session.invalidate();
            }

            // Clear security context
            SecurityContextHolder.clearContext();

            // Log logout
            securityLogger.info("User '{}' logged out from IP: {}", username, ipAddress);
            securityAuditService.logUserLogout(username, ipAddress, true, null);

            return ResponseEntity.ok(Map.of("message", "Logout successful"));

        } catch (Exception e) {
            logger.error("Logout error for user '{}' from IP {}: {}", username, ipAddress, e.getMessage());
            securityAuditService.logUserLogout(username, ipAddress, false, e.getMessage());
            return ResponseEntity.ok(Map.of("message", "Logout completed"));
        }
    }

    /**
     * Get current user information.
     */
    @GetMapping("/current")
    public ResponseEntity<?> getCurrentUser(Principal principal) {
        if (principal == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of(
                "error", "Not authenticated"
            ));
        }

        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            CustomUserPrincipal userPrincipal = (CustomUserPrincipal) authentication.getPrincipal();

            Map<String, Object> response = new HashMap<>();
            response.put("userId", userPrincipal.getId());
            response.put("username", userPrincipal.getUsername());
            response.put("firstname", userPrincipal.getFirstname());
            response.put("lastname", userPrincipal.getLastname());
            response.put("email", userPrincipal.getEmail());
            response.put("roles", userPrincipal.getAuthorities().stream()
                .map(authority -> authority.getAuthority())
                .collect(Collectors.toList()));
            response.put("isAdmin", userPrincipal.isAdmin());

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            logger.error("Error getting current user: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of(
                "error", "Failed to get user information"
            ));
        }
    }

    /**
     * Enhanced user registration with comprehensive validation and security checks.
     */
    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody UserRegistrationDTO registrationDTO, 
                                    BindingResult bindingResult, 
                                    HttpServletRequest request) {
        
        String ipAddress = getClientIpAddress(request);

        try {
            // Check validation errors
            if (bindingResult.hasErrors()) {
                Map<String, String> errors = new HashMap<>();
                for (FieldError error : bindingResult.getFieldErrors()) {
                    errors.put(error.getField(), error.getDefaultMessage());
                }
                return ResponseEntity.badRequest().body(Map.of("fieldErrors", errors));
            }

            // Log registration attempt
            securityLogger.info("Registration attempt for username '{}' from IP: {}", 
                               registrationDTO.getUsername(), ipAddress);

            // Input validation
            inputValidationService.validateInput(registrationDTO.getUsername(), "username");
            inputValidationService.validateInput(registrationDTO.getEmail(), "email");

            // Create user
            User user = userService.createUser(registrationDTO);

            // Log successful registration
            securityLogger.info("User '{}' registered successfully from IP: {}", 
                               user.getUsername(), ipAddress);

            securityAuditService.logUserRegistration(
                user.getUsername(), ipAddress, true, "Registration successful");

            return ResponseEntity.ok(Map.of(
                "message", "User registered successfully",
                "username", user.getUsername()
            ));

        } catch (IllegalArgumentException e) {
            securityLogger.warn("Registration failed for username '{}' from IP: {}, reason: {}", 
                               registrationDTO.getUsername(), ipAddress, e.getMessage());

            securityAuditService.logUserRegistration(
                registrationDTO.getUsername(), ipAddress, false, e.getMessage());

            return ResponseEntity.badRequest().body(Map.of(
                "error", e.getMessage()
            ));

        } catch (Exception e) {
            logger.error("Registration error for username '{}' from IP {}: {}", 
                        registrationDTO.getUsername(), ipAddress, e.getMessage());

            securityAuditService.logUserRegistration(
                registrationDTO.getUsername(), ipAddress, false, "System error");

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of(
                "error", "Registration failed"
            ));
        }
    }

    /**
     * Get client IP address from request.
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
     * Inner class for login requests with validation.
     */
    public static class LoginRequest {
        @NotBlank(message = "Username is required")
        @NoSqlInjection
        @NoXSS
        private String username;

        @NotBlank(message = "Password is required")
        @NoSqlInjection
        @NoXSS
        private String password;

        // Constructors, getters, and setters
        public LoginRequest() {}

        public LoginRequest(String username, String password) {
            this.username = username;
            this.password = password;
        }

        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }

        public String getPassword() { return password; }
        public void setPassword(String password) { this.password = password; }
    }
}