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
     * Enhanced user registration with comprehensive validation and security checks.
     */
    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody UserRegistrationDTO registrationDTO, 
                                    BindingResult bindingResult,
                                    HttpServletRequest request) {
        
        String ipAddress = getClientIpAddress(request);
        
        try {
            // Log registration attempt
            securityLogger.info("Registration attempt for username '{}' from IP: {}", 
                               registrationDTO.getUsername(), ipAddress);

            // Check for validation errors
            if (bindingResult.hasErrors()) {
                Map<String, String> errors = new HashMap<>();
                for (FieldError error : bindingResult.getFieldErrors()) {
                    errors.put(error.getField(), error.getDefaultMessage());
                }
                
                securityLogger.warn("Registration validation failed for '{}' from IP {}: {}", 
                                   registrationDTO.getUsername(), ipAddress, errors);
                
                return ResponseEntity.badRequest().body(Map.of(
                    "error", "Validation failed",
                    "details", errors
                ));
            }

            // Additional security validation
            inputValidationService.validateInput(registrationDTO.getUsername(), "username");
            inputValidationService.validateInput(registrationDTO.getEmail(), "email");
            inputValidationService.validateInput(registrationDTO.getFirstname(), "firstname");
            inputValidationService.validateInput(registrationDTO.getLastname(), "lastname");

            // Check if user already exists
            if (userService.existsByUsername(registrationDTO.getUsername())) {
                securityLogger.warn("Registration attempt with existing username '{}' from IP: {}", 
                                   registrationDTO.getUsername(), ipAddress);
                return ResponseEntity.badRequest().body(Map.of(
                    "error", "Username already exists"
                ));
            }

            if (userService.existsByEmail(registrationDTO.getEmail())) {
                securityLogger.warn("Registration attempt with existing email '{}' from IP: {}", 
                                   registrationDTO.getEmail(), ipAddress);
                return ResponseEntity.badRequest().body(Map.of(
                    "error", "Email already exists"
                ));
            }

            // Create user
            User user = userService.createUser(registrationDTO);
            
            // Log successful registration
            securityLogger.info("User '{}' registered successfully from IP: {}", 
                               user.getUsername(), ipAddress);
            
            securityAuditService.logUserRegistration(user.getUsername(), ipAddress, true, null);

            return ResponseEntity.ok(Map.of(
                "message", "User registered successfully",
                "userId", user.getId(),
                "username", user.getUsername()
            ));

        } catch (SecurityException e) {
            securityLogger.error("Security violation during registration from IP {}: {}", 
                                ipAddress, e.getMessage());
            
            securityAuditService.logUserRegistration(
                registrationDTO.getUsername(), ipAddress, false, "Security violation: " + e.getMessage());
            
            return ResponseEntity.badRequest().body(Map.of(
                "error", "Registration failed due to security violation"
            ));
            
        } catch (Exception e) {
            logger.error("Registration failed for user '{}' from IP {}: {}", 
                        registrationDTO.getUsername(), ipAddress, e.getMessage());
            
            securityAuditService.logUserRegistration(
                registrationDTO.getUsername(), ipAddress, false, "System error: " + e.getMessage());
            
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of(
                "error", "Registration failed"
            ));
        }
    }

    /**
     * Enhanced login endpoint with rate limiting and comprehensive security logging.
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest loginRequest, 
                                HttpServletRequest request) {
        
        String ipAddress = getClientIpAddress(request);
        
        try {
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
                    loginRequest.getUsername(), 
                    loginRequest.getPassword()
                )
            );

            // Clear failed attempts on successful authentication
            rateLimitingService.clearFailedAttempts(ipAddress);

            // Create secure session
            SecurityContextHolder.getContext().setAuthentication(authentication);
            HttpSession session = request.getSession(true);
            
            // Session security settings
            session.setMaxInactiveInterval(3600); // 1 hour
            session.setAttribute("SPRING_SECURITY_CONTEXT", SecurityContextHolder.getContext());
            
            // Update user's last login
            CustomUserPrincipal userPrincipal = (CustomUserPrincipal) authentication.getPrincipal();
            userService.updateLastLogin(userPrincipal.getId());

            // Log successful login
            securityLogger.info("User '{}' logged in successfully from IP: {}", 
                               loginRequest.getUsername(), ipAddress);
            
            securityAuditService.logUserLogin(loginRequest.getUsername(), ipAddress, true, null);

            // Return user info
            return ResponseEntity.ok(Map.of(
                "message", "Login successful",
                "sessionId", session.getId(),
                "userId", userPrincipal.getId(),
                "username", userPrincipal.getUsername(),
                "firstname", userPrincipal.getFirstname(),
                "lastname", userPrincipal.getLastname(),
                "roles", userPrincipal.getAuthorities().stream()
                    .map(auth -> auth.getAuthority())
                    .collect(Collectors.toList()),
                "isAdmin", userPrincipal.getAuthorities().stream()
                    .anyMatch(auth -> auth.getAuthority().equals("ROLE_ADMIN"))
            ));

        } catch (BadCredentialsException e) {
            // Record failed attempt for rate limiting
            rateLimitingService.recordFailedAttempt(ipAddress);
            
            // Log failed attempt
            securityLogger.warn("Failed login attempt for user '{}' from IP: {} (attempt #{}) - Invalid credentials", 
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
                        loginRequest.getUsername(), ipAddress, e.getMessage());
            
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

            // Log successful logout
            securityLogger.info("User '{}' logged out successfully from IP: {}", username, ipAddress);
            securityAuditService.logUserLogout(username, ipAddress, true, null);

            return ResponseEntity.ok(Map.of("message", "Logout successful"));

        } catch (Exception e) {
            logger.error("Logout error for user '{}' from IP {}: {}", username, ipAddress, e.getMessage());
            securityAuditService.logUserLogout(username, ipAddress, false, e.getMessage());
            
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of(
                "message", "Logout failed"
            ));
        }
    }

    /**
     * Get current authenticated user information with enhanced security validation.
     */
    @GetMapping("/current")
    public ResponseEntity<?> getCurrentUser(Principal principal, HttpServletRequest request) {
        
        String ipAddress = getClientIpAddress(request);
        
        try {
            if (principal == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
            }

            User user = userService.findByUsername(principal.getName())
                .orElseThrow(() -> new RuntimeException("User not found"));

            // Log access to user info
            securityLogger.debug("User info accessed by '{}' from IP: {}", user.getUsername(), ipAddress);

            Map<String, Object> response = new HashMap<>();
            response.put("userId", user.getId());
            response.put("username", user.getUsername());
            response.put("firstname", user.getFirstname());
            response.put("lastname", user.getLastname());
            response.put("email", user.getEmail());
            response.put("roles", user.getRoles().stream()
                .map(Role::getName)
                .collect(Collectors.toList()));
            response.put("isAdmin", userService.isAdmin(user));
            response.put("lastLogin", user.getLastLogin());

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            logger.error("Error getting current user info from IP {}: {}", ipAddress, e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }

    /**
     * Extract client IP address from request headers.
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