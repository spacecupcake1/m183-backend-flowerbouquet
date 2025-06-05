package com.bbzbl.flowerbouquet.user;

import java.security.Principal;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;

/**
 * REST controller for session-based user management.
 */
@RestController
@CrossOrigin(origins = "http://localhost:4200", allowCredentials = "true")
@RequestMapping("/api/users")
public class UserController {

    @Autowired
    private UserService userService;
    
    @Autowired
    private PasswordEncoder passwordEncoder;
    
    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserRepository userRepository;

    /**
     * Register a new user with validation.
     */
    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@Valid @RequestBody UserRegistrationDTO registrationDTO, 
                                         BindingResult bindingResult) {
        try {
            // Check for validation errors
            if (bindingResult.hasErrors()) {
                Map<String, String> errors = new HashMap<>();
                for (FieldError error : bindingResult.getFieldErrors()) {
                    errors.put(error.getField(), error.getDefaultMessage());
                }
                return ResponseEntity.badRequest().body(createErrorResponse("Validation failed", errors));
            }

            // Check if username exists
            if (userService.existsByUsername(registrationDTO.getUsername())) {
                return ResponseEntity.badRequest()
                    .body(createErrorResponse("Username already exists"));
            }

            // Check if email exists
            if (userService.existsByEmail(registrationDTO.getEmail())) {
                return ResponseEntity.badRequest()
                    .body(createErrorResponse("Email already exists"));
            }

            // Create user from DTO
            User user = new User();
            user.setUsername(registrationDTO.getUsername().trim());
            user.setFirstname(registrationDTO.getFirstname().trim());
            user.setLastname(registrationDTO.getLastname().trim());
            user.setEmail(registrationDTO.getEmail().trim().toLowerCase());
            
            // Hash the password
            user.setPassword(passwordEncoder.encode(registrationDTO.getPassword()));

            User createdUser = userService.createUser(user);
            
            // Return success response
            Map<String, Object> response = new HashMap<>();
            response.put("message", "User registered successfully");
            response.put("userId", createdUser.getId());
            response.put("username", createdUser.getUsername());
            response.put("firstname", createdUser.getFirstname());
            response.put("lastname", createdUser.getLastname());
            response.put("email", createdUser.getEmail());
            
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                .body(createErrorResponse("Registration failed: " + e.getMessage()));
        }
    }
    
    /**
     * Login user with session creation.
     */
    @PostMapping("/login")
    public ResponseEntity<?> loginUser(@RequestBody UserLoginDTO loginDTO, 
                                      HttpServletRequest request) {
        try {
            // Validate input
            if (loginDTO.getUsername() == null || loginDTO.getUsername().trim().isEmpty()) {
                return ResponseEntity.badRequest()
                    .body(createErrorResponse("Username is required"));
            }
            if (loginDTO.getPassword() == null || loginDTO.getPassword().trim().isEmpty()) {
                return ResponseEntity.badRequest()
                    .body(createErrorResponse("Password is required"));
            }

            // Authenticate user
            Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                    loginDTO.getUsername().trim(), 
                    loginDTO.getPassword()
                )
            );

            // Set authentication in security context
            SecurityContextHolder.getContext().setAuthentication(authentication);

            // Create session
            HttpSession session = request.getSession(true);
            session.setAttribute("SPRING_SECURITY_CONTEXT", SecurityContextHolder.getContext());

            // Get user details
            Optional<User> userOptional = userService.findByUsername(loginDTO.getUsername().trim());
            
            if (userOptional.isPresent()) {
                User user = userOptional.get();
                
                Map<String, Object> response = new HashMap<>();
                response.put("message", "Login successful");
                response.put("sessionId", session.getId());
                response.put("userId", user.getId());
                response.put("username", user.getUsername());
                response.put("firstname", user.getFirstname());
                response.put("lastname", user.getLastname());
                response.put("email", user.getEmail());
                
                // Add role information
                if (user.getRoles() != null && !user.getRoles().isEmpty()) {
                    List<String> roleNames = user.getRoles().stream()
                            .map(role -> role.getName())
                            .collect(Collectors.toList());
                    response.put("roles", roleNames);
                    response.put("isAdmin", userService.isAdmin(user));
                } else {
                    response.put("roles", List.of("ROLE_USER"));
                    response.put("isAdmin", false);
                }
                
                return ResponseEntity.ok(response);
            }
            
            return ResponseEntity.status(401)
                .body(createErrorResponse("Authentication failed"));
                
        } catch (Exception e) {
            return ResponseEntity.status(401)
                .body(createErrorResponse("Invalid username or password"));
        }
    }

    /**
     * Logout user and invalidate session.
     */
    @PostMapping("/logout")
    public ResponseEntity<?> logoutUser(HttpServletRequest request) {
        try {
            HttpSession session = request.getSession(false);
            if (session != null) {
                session.invalidate();
            }
            SecurityContextHolder.clearContext();
            
            Map<String, String> response = new HashMap<>();
            response.put("message", "Logout successful");
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            return ResponseEntity.status(500)
                .body(createErrorResponse("Logout failed"));
        }
    }

    /**
     * Get current user information.
     */
    @GetMapping("/current")
    public ResponseEntity<?> getCurrentUser(Principal principal) {
        if (principal == null) {
            return ResponseEntity.status(401)
                .body(createErrorResponse("User not authenticated"));
        }

        Optional<User> userOptional = userService.findByUsername(principal.getName());
        
        if (userOptional.isPresent()) {
            User user = userOptional.get();
            
            Map<String, Object> response = new HashMap<>();
            response.put("userId", user.getId());
            response.put("username", user.getUsername());
            response.put("firstname", user.getFirstname());
            response.put("lastname", user.getLastname());
            response.put("email", user.getEmail());
            
            if (user.getRoles() != null && !user.getRoles().isEmpty()) {
                List<String> roleNames = user.getRoles().stream()
                        .map(role -> role.getName())
                        .collect(Collectors.toList());
                response.put("roles", roleNames);
                response.put("isAdmin", userService.isAdmin(user));
            } else {
                response.put("roles", List.of("ROLE_USER"));
                response.put("isAdmin", false);
            }
            
            return ResponseEntity.ok(response);
        }
        
        return ResponseEntity.status(404)
            .body(createErrorResponse("User not found"));
    }

    /**
     * Get all users (admin only).
     */
    @GetMapping("")
    public ResponseEntity<List<UserResponseDTO>> getAllUsers() {
        List<User> users = userService.getAllUsers();
        List<UserResponseDTO> userDTOs = users.stream()
            .map(this::convertToResponseDTO)
            .collect(Collectors.toList());
        return ResponseEntity.ok(userDTOs);
    }

    /**
     * Get a user by ID.
     */
    @GetMapping("/{id}")
    public ResponseEntity<UserResponseDTO> getUserById(@PathVariable Long id) {
        Optional<User> user = userService.getUserById(id);
        return user.map(u -> ResponseEntity.ok(convertToResponseDTO(u)))
                   .orElseGet(() -> ResponseEntity.notFound().build());
    }

    /**
     * Check if a user has admin privileges.
     */
    @GetMapping("/{id}/is-admin")
    public ResponseEntity<Map<String, Boolean>> isUserAdmin(@PathVariable Long id) {
        Optional<User> user = userService.getUserById(id);
        
        if (user.isPresent()) {
            Map<String, Boolean> response = new HashMap<>();
            response.put("isAdmin", userService.isAdmin(user.get()));
            return ResponseEntity.ok(response);
        } else {
            return ResponseEntity.notFound().build();
        }
    }

    // Helper methods
    private Map<String, Object> createErrorResponse(String message) {
        Map<String, Object> response = new HashMap<>();
        response.put("error", message);
        return response;
    }
    
    private Map<String, Object> createErrorResponse(String message, Map<String, String> fieldErrors) {
        Map<String, Object> response = new HashMap<>();
        response.put("error", message);
        response.put("fieldErrors", fieldErrors);
        return response;
    }
    
    private UserResponseDTO convertToResponseDTO(User user) {
        UserResponseDTO dto = new UserResponseDTO();
        dto.setId(user.getId());
        dto.setUsername(user.getUsername());
        dto.setFirstname(user.getFirstname());
        dto.setLastname(user.getLastname());
        dto.setEmail(user.getEmail());
        if (user.getRoles() != null) {
            dto.setRoles(user.getRoles().stream()
                .map(role -> role.getName())
                .collect(Collectors.toList()));
        }
        return dto;
    }
}