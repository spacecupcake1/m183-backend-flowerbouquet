package com.bbzbl.flowerbouquet.security;

import java.security.Principal;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.bbzbl.flowerbouquet.user.User;
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

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserService userService;

    @Autowired
    private PasswordEncoder passwordEncoder;

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

            // Get sanitized values using your method name
            String username = usernameResult.getSanitized();
            String firstname = firstnameResult.getSanitized();
            String lastname = lastnameResult.getSanitized();
            String email = emailResult.getSanitized();
            String password = registrationRequest.getPassword(); // Don't sanitize passwords

            // Additional validation using your specific validation methods
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

            // Password security validation using your method
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

            // Create user with encoded password (includes salt + pepper)
            User user = new User();
            user.setUsername(username);
            user.setFirstname(firstname);
            user.setLastname(lastname);
            user.setEmail(email);
            user.setPassword(passwordEncoder.encode(addPepper(password)));

            User savedUser = userService.createUser(user);

            response.put("message", "User registered successfully");
            response.put("userId", savedUser.getId());
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
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest, HttpServletRequest request) {
        
        Map<String, Object> response = new HashMap<>();
        
        try {
            System.out.println("=== LOGIN DEBUG START ===");
            System.out.println("Raw login request: " + loginRequest.getUsername() + " / " + (loginRequest.getPassword() != null ? "***" : "null"));
            
            // Validate and sanitize inputs using your InputValidationService
            InputValidationService.ValidationResult usernameResult = inputValidationService.validateAndSanitize(loginRequest.getUsername());
            
            if (!usernameResult.isValid()) {
                System.out.println("Username validation failed: " + usernameResult.getError());
                response.put("message", "Invalid input format: " + usernameResult.getError());
                return ResponseEntity.badRequest().body(response);
            }
            
            String username = usernameResult.getSanitized();
            String password = loginRequest.getPassword(); // Don't sanitize password

            System.out.println("Sanitized username: " + username);
            System.out.println("Password present: " + (password != null && !password.isEmpty()));

            // Check for null/empty values (this was the issue - username was null)
            if (username == null || username.trim().isEmpty()) {
                System.out.println("Username is null or empty after sanitization");
                response.put("message", "Username cannot be empty");
                return ResponseEntity.badRequest().body(response);
            }
            
            if (password == null || password.trim().isEmpty()) {
                System.out.println("Password is null or empty");
                response.put("message", "Password cannot be empty");
                return ResponseEntity.badRequest().body(response);
            }

            // Additional username validation
            if (!inputValidationService.isValidUsername(username)) {
                System.out.println("Username format validation failed");
                response.put("message", "Invalid username format");
                return ResponseEntity.badRequest().body(response);
            }

            // Password security check (without sanitizing to preserve special characters)
            if (!inputValidationService.isSecurePassword(password)) {
                System.out.println("Password security check failed");
                response.put("message", "Password contains potentially dangerous content");
                return ResponseEntity.badRequest().body(response);
            }

            // Check if user exists in database
            User user = userService.findByUsername(username).orElse(null);
            if (user == null) {
                System.out.println("User not found in database: " + username);
                response.put("message", "Invalid username or password");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
            }
            
            System.out.println("User found in database: " + user.getUsername());
            System.out.println("User enabled: " + user.isEnabled());
            System.out.println("Account non-locked: " + user.isAccountNonLocked());

            // Add pepper to password for authentication
            String pepperedPassword = addPepper(password);
            System.out.println("Pepper used: " + pepper);
            System.out.println("Password with pepper length: " + pepperedPassword.length());

            // Check stored password hash
            System.out.println("Stored password hash: " + user.getPassword());
            
            // Test password matching manually
            boolean passwordMatches = passwordEncoder.matches(pepperedPassword, user.getPassword());
            System.out.println("Password matches: " + passwordMatches);

            // Authenticate user
            Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, pepperedPassword)
            );

            System.out.println("Authentication successful: " + authentication.isAuthenticated());

            // IMPORTANT: Set authentication in security context for session
            SecurityContextHolder.getContext().setAuthentication(authentication);

            // Create new session for security (session fixation protection)
            HttpSession oldSession = request.getSession(false);
            if (oldSession != null) {
                oldSession.invalidate(); // Invalidate old session
            }
            
            HttpSession newSession = request.getSession(true); // Create new session
            newSession.setAttribute("SPRING_SECURITY_CONTEXT", SecurityContextHolder.getContext());
            newSession.setAttribute("userId", user.getId());
            newSession.setAttribute("username", user.getUsername());
            newSession.setMaxInactiveInterval(30 * 60); // 30 minutes

            // Update user's last login time
            user.setLastLogin(java.time.LocalDateTime.now());
            userService.save(user); // You might need to add this method to UserService

            // Prepare response
            response.put("message", "Login successful");
            response.put("sessionId", newSession.getId());
            response.put("userId", user.getId());
            response.put("username", user.getUsername());
            response.put("firstname", user.getFirstname());
            response.put("lastname", user.getLastname());
            response.put("email", user.getEmail());
            response.put("roles", user.getRoles().stream()
                .map(Role::getName)
                .collect(Collectors.toList()));
            response.put("isAdmin", userService.isAdmin(user));

            System.out.println("=== LOGIN DEBUG END - SUCCESS ===");
            return ResponseEntity.ok(response);

        } catch (BadCredentialsException e) {
            System.out.println("BadCredentialsException: " + e.getMessage());
            System.out.println("=== LOGIN DEBUG END - BAD CREDENTIALS ===");
            response.put("message", "Invalid username or password");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        } catch (SecurityException e) {
            System.out.println("SecurityException: " + e.getMessage());
            System.out.println("=== LOGIN DEBUG END - SECURITY ERROR ===");
            response.put("message", "Security validation failed");
            return ResponseEntity.badRequest().body(response);
        } catch (Exception e) {
            System.out.println("General Exception: " + e.getMessage());
            e.printStackTrace();
            System.out.println("=== LOGIN DEBUG END - GENERAL ERROR ===");
            response.put("message", "Login failed: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
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
     * Add pepper to password for additional security.
     * Pepper is now loaded from environment variables for security.
     */
    private String addPepper(String password) {
        return password + pepper;
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
}