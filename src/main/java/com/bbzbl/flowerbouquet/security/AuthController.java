package com.bbzbl.flowerbouquet.security;

import java.security.Principal;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.bbzbl.flowerbouquet.security.UserDetailsServiceImpl.CustomUserPrincipal;
import com.bbzbl.flowerbouquet.user.User;
import com.bbzbl.flowerbouquet.user.UserRegistrationDTO;
import com.bbzbl.flowerbouquet.user.UserService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;

/**
 * REST Controller for handling authentication operations.
 * Provides secure login, logout, registration, and user session management.
 */
@RestController
@RequestMapping("/api/users")
public class AuthController {

    // ADD THIS LOGGER FIELD - THIS FIXES THE ERROR
    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserService userService;

    // @Autowired
    // private PasswordEncoder passwordEncoder;

    @Autowired
    private InputValidationService inputValidationService;

    // Security configuration from environment variables
    @Value("${app.security.pepper:MySecretPepperKey2024!@#$%^&*()}")
    private String pepper;

    /**
     * User registration endpoint with comprehensive validation and security checks.
     */
    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@Valid @RequestBody UserRegistrationRequest registrationRequest, 
                                        BindingResult bindingResult) {
        
        Map<String, Object> response = new HashMap<>();
        
        try {
            // Validate and sanitize all inputs using your InputValidationService
            InputValidationService.ValidationResult usernameResult = inputValidationService.validateAndSanitize(registrationRequest.getUsername());
            InputValidationService.ValidationResult firstnameResult = inputValidationService.validateAndSanitize(registrationRequest.getFirstname());
            InputValidationService.ValidationResult lastnameResult = inputValidationService.validateAndSanitize(registrationRequest.getLastname());
            InputValidationService.ValidationResult emailResult = inputValidationService.validateAndSanitize(registrationRequest.getEmail());
            
            // Check if validation failed using your ValidationResult structure
            if (!usernameResult.isValid() || !firstnameResult.isValid() || !lastnameResult.isValid() || !emailResult.isValid()) {
                Map<String, String> fieldErrors = new HashMap<>();
                if (!usernameResult.isValid()) fieldErrors.put("username", usernameResult.getError());
                if (!firstnameResult.isValid()) fieldErrors.put("firstname", firstnameResult.getError());
                if (!lastnameResult.isValid()) fieldErrors.put("lastname", lastnameResult.getError());
                if (!emailResult.isValid()) fieldErrors.put("email", emailResult.getError());
                
                response.put("error", "Input validation failed");
                response.put("fieldErrors", fieldErrors);
                return ResponseEntity.badRequest().body(response);
            }

            // Get sanitized values
            String username = usernameResult.getSanitized();
            String firstname = firstnameResult.getSanitized();
            String lastname = lastnameResult.getSanitized();
            String email = emailResult.getSanitized();
            String password = registrationRequest.getPassword(); // Don't sanitize passwords

            // Additional validation checks
            if (!inputValidationService.isValidUsername(username)) {
                response.put("error", "Invalid username format");
                Map<String, String> fieldErrors = new HashMap<>();
                fieldErrors.put("username", "Username contains invalid characters or format");
                response.put("fieldErrors", fieldErrors);
                return ResponseEntity.badRequest().body(response);
            }

            if (!inputValidationService.isValidName(firstname)) {
                response.put("error", "Invalid first name format");
                Map<String, String> fieldErrors = new HashMap<>();
                fieldErrors.put("firstname", "First name contains invalid characters or format");
                response.put("fieldErrors", fieldErrors);
                return ResponseEntity.badRequest().body(response);
            }

            if (!inputValidationService.isValidName(lastname)) {
                response.put("error", "Invalid last name format");
                Map<String, String> fieldErrors = new HashMap<>();
                fieldErrors.put("lastname", "Last name contains invalid characters or format");
                response.put("fieldErrors", fieldErrors);
                return ResponseEntity.badRequest().body(response);
            }

            if (!inputValidationService.isValidEmail(email)) {
                response.put("error", "Invalid email format");
                Map<String, String> fieldErrors = new HashMap<>();
                fieldErrors.put("email", "Email format is invalid");
                response.put("fieldErrors", fieldErrors);
                return ResponseEntity.badRequest().body(response);
            }

            // Validation errors from Bean Validation annotations
            if (bindingResult.hasErrors()) {
                Map<String, String> fieldErrors = new HashMap<>();
                for (FieldError error : bindingResult.getFieldErrors()) {
                    fieldErrors.put(error.getField(), error.getDefaultMessage());
                }
                response.put("error", "Validation failed");
                response.put("fieldErrors", fieldErrors);
                return ResponseEntity.badRequest().body(response);
            }

            // Business logic validation
            if (userService.existsByUsername(username)) {
                response.put("error", "Username already exists");
                Map<String, String> fieldErrors = new HashMap<>();
                fieldErrors.put("username", "Username is already taken");
                response.put("fieldErrors", fieldErrors);
                return ResponseEntity.badRequest().body(response);
            }

            if (userService.existsByEmail(email)) {
                response.put("error", "Email already exists");
                Map<String, String> fieldErrors = new HashMap<>();
                fieldErrors.put("email", "Email is already registered");
                response.put("fieldErrors", fieldErrors);
                return ResponseEntity.badRequest().body(response);
            }

            // Password security validation
            if (!inputValidationService.isSecurePassword(password)) {
                response.put("error", "Password does not meet security requirements");
                Map<String, String> fieldErrors = new HashMap<>();
                fieldErrors.put("password", "Password may contain dangerous content or is not secure enough");
                response.put("fieldErrors", fieldErrors);
                return ResponseEntity.badRequest().body(response);
            }

            // Additional password strength validation
            if (!isPasswordStrong(password)) {
                response.put("error", "Password does not meet security requirements");
                Map<String, String> fieldErrors = new HashMap<>();
                fieldErrors.put("password", "Password must contain at least 8 characters, including uppercase, lowercase, number, and special character");
                response.put("fieldErrors", fieldErrors);
                return ResponseEntity.badRequest().body(response);
            }

            // FIXED: Convert UserRegistrationRequest to UserRegistrationDTO
            UserRegistrationDTO dto = new UserRegistrationDTO();
            dto.setUsername(username);
            dto.setFirstname(firstname);
            dto.setLastname(lastname);
            dto.setEmail(email);
            dto.setPassword(password);

            // Create user using the DTO
            User createdUser = userService.createUser(dto);

            // FIXED: Use createdUser instead of savedUser
            response.put("message", "User registered successfully");
            response.put("userId", createdUser.getId());
            return ResponseEntity.ok(response);

        } catch (SecurityException e) {
            response.put("error", "Security validation failed");
            return ResponseEntity.badRequest().body(response);
        } catch (Exception e) {
            response.put("error", "Registration failed: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }

    /**
     * Secure login endpoint with session management and authentication.
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest loginRequest, 
                                HttpServletRequest request) {
        try {
            // Input validation
            inputValidationService.validateInput(loginRequest.getUsername(), "username");
            
            // Rate limiting check (commented out for now)
            // rateLimitingService.checkLoginAttempts(request.getRemoteAddr());
            
            // Authenticate user
            Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                    loginRequest.getUsername(), 
                    loginRequest.getPassword()
                )
            );
            
            // Create secure session
            SecurityContextHolder.getContext().setAuthentication(authentication);
            HttpSession session = request.getSession(true);
            
            // Session security settings
            session.setMaxInactiveInterval(3600); // 1 hour
            session.setAttribute("SPRING_SECURITY_CONTEXT", 
                            SecurityContextHolder.getContext());
            
            // Log successful login - NOW LOGGER WORKS
            logger.info("User {} logged in successfully from IP: {}", 
                    loginRequest.getUsername(), request.getRemoteAddr());
            
            // Return user info
            CustomUserPrincipal userPrincipal = (CustomUserPrincipal) authentication.getPrincipal();
            
            return ResponseEntity.ok(Map.of(
                "message", "Login successful",
                "sessionId", session.getId(),
                "userId", userPrincipal.getId(),
                "username", userPrincipal.getUsername(),
                "roles", userPrincipal.getAuthorities().stream()
                    .map(auth -> auth.getAuthority())
                    .collect(Collectors.toList()),
                "isAdmin", userPrincipal.getAuthorities().stream()
                    .anyMatch(auth -> auth.getAuthority().equals("ROLE_ADMIN"))
            ));
            
        } catch (BadCredentialsException e) {
            // Log failed attempt - NOW LOGGER WORKS
            logger.warn("Failed login attempt for user {} from IP: {}", 
                    loginRequest.getUsername(), request.getRemoteAddr());
            
            // Increment failed attempts (commented out for now)
            // rateLimitingService.recordFailedAttempt(request.getRemoteAddr());
            
            return ResponseEntity.status(401)
                .body(Map.of("error", "Invalid username or password"));
        }
    }

    /**
     * Secure logout endpoint with session invalidation.
     */
    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request) {
        try {
            // Invalidate session
            HttpSession session = request.getSession(false);
            if (session != null) {
                session.invalidate();
            }

            // Clear security context
            SecurityContextHolder.clearContext();

            Map<String, String> response = new HashMap<>();
            response.put("message", "Logout successful");
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            Map<String, String> response = new HashMap<>();
            response.put("message", "Logout failed");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }

    /**
     * Get current authenticated user information.
     */
    @GetMapping("/current")
    public ResponseEntity<?> getCurrentUser(Principal principal) {
        try {
            if (principal == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
            }

            User user = userService.findByUsername(principal.getName())
                .orElseThrow(() -> new RuntimeException("User not found"));

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

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }

    /**
     * Validate password strength (additional check beyond InputValidationService).
     */
    private boolean isPasswordStrong(String password) {
        if (password == null || password.length() < 8) {
            return false;
        }

        boolean hasUppercase = password.chars().anyMatch(Character::isUpperCase);
        boolean hasLowercase = password.chars().anyMatch(Character::isLowerCase);
        boolean hasDigit = password.chars().anyMatch(Character::isDigit);
        boolean hasSpecialChar = password.chars().anyMatch(ch -> "!@#$%^&*()_+-=[]{}|;:,.<>?".indexOf(ch) >= 0);

        return hasUppercase && hasLowercase && hasDigit && hasSpecialChar;
    }

    /**
     * Inner class for registration requests.
     */
    public static class UserRegistrationRequest {
        @jakarta.validation.constraints.NotBlank(message = "Username is required")
        @jakarta.validation.constraints.Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
        private String username;

        @jakarta.validation.constraints.NotBlank(message = "First name is required")
        @jakarta.validation.constraints.Size(min = 2, max = 50, message = "First name must be between 2 and 50 characters")
        private String firstname;

        @jakarta.validation.constraints.NotBlank(message = "Last name is required")
        @jakarta.validation.constraints.Size(min = 2, max = 50, message = "Last name must be between 2 and 50 characters")
        private String lastname;

        @jakarta.validation.constraints.NotBlank(message = "Email is required")
        @jakarta.validation.constraints.Email(message = "Email must be valid")
        @jakarta.validation.constraints.Size(max = 100, message = "Email cannot exceed 100 characters")
        private String email;

        @jakarta.validation.constraints.NotBlank(message = "Password is required")
        @jakarta.validation.constraints.Size(min = 6, max = 100, message = "Password must be between 6 and 100 characters")
        private String password;

        // Getters and setters
        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }
        public String getFirstname() { return firstname; }
        public void setFirstname(String firstname) { this.firstname = firstname; }
        public String getLastname() { return lastname; }
        public void setLastname(String lastname) { this.lastname = lastname; }
        public String getEmail() { return email; }
        public void setEmail(String email) { this.email = email; }
        public String getPassword() { return password; }
        public void setPassword(String password) { this.password = password; }
    }

    /**
     * Inner class for login requests.
     */
    public static class LoginRequest {
        private String username;
        private String password;

        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }
        public String getPassword() { return password; }
        public void setPassword(String password) { this.password = password; }
    }

    /**
     * Create first admin user (only works if no admin exists)
     */
    @PostMapping("/create-admin")
    public ResponseEntity<?> createFirstAdmin(@Valid @RequestBody UserRegistrationRequest request) {
        
        Map<String, Object> response = new HashMap<>();
        
        try {
            // Check if any admin already exists
            boolean adminExists = userService.getAllUsers().stream()
                .anyMatch(user -> userService.isAdmin(user));
            
            if (adminExists) {
                response.put("error", "Admin user already exists");
                return ResponseEntity.badRequest().body(response);
            }
            
            // Convert to DTO
            UserRegistrationDTO dto = new UserRegistrationDTO();
            dto.setUsername(request.getUsername());
            dto.setFirstname(request.getFirstname());
            dto.setLastname(request.getLastname());
            dto.setEmail(request.getEmail());
            dto.setPassword(request.getPassword());
            
            // Create user
            User adminUser = userService.createUser(dto);
            
            // Add admin role
            userService.addRoleToUser(adminUser.getId(), "ROLE_ADMIN");
            
            response.put("message", "Admin user created successfully");
            response.put("userId", adminUser.getId());
            response.put("username", adminUser.getUsername());
            
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            response.put("error", "Failed to create admin: " + e.getMessage());
            return ResponseEntity.status(500).body(response);
        }
    }
}