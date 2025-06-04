package com.bbzbl.flowerbouquet.user;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.bbzbl.flowerbouquet.security.Role;
import com.bbzbl.flowerbouquet.security.RoleRepository;

import jakarta.validation.Valid;

/**
 * Secure admin user management endpoints.
 */
@RestController
@CrossOrigin(origins = "http://localhost:4200", allowCredentials = "true")
@RequestMapping("/api/admin")
public class AdminUserController {

    @Autowired
    private UserService userService;
    
    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private RoleRepository roleRepository;
    
    @Autowired
    private PasswordEncoder passwordEncoder;

    /**
     * Create first admin user (only if no admin exists).
     */
    @PostMapping("/create-first-admin")
    public ResponseEntity<?> createFirstAdmin(@Valid @RequestBody AdminCreationDTO adminData) {
        try {
            // Check if any admin already exists
            boolean adminExists = userRepository.findAll().stream()
                .anyMatch(user -> user.getRoles() != null && 
                    user.getRoles().stream().anyMatch(role -> "ROLE_ADMIN".equals(role.getName())));
            
            if (adminExists) {
                return ResponseEntity.badRequest()
                    .body(createErrorResponse("Admin user already exists"));
            }
            
            // Check if username is taken
            if (userService.existsByUsername(adminData.getUsername())) {
                return ResponseEntity.badRequest()
                    .body(createErrorResponse("Username already exists"));
            }
            
            // Check if email is taken
            if (userService.existsByEmail(adminData.getEmail())) {
                return ResponseEntity.badRequest()
                    .body(createErrorResponse("Email already exists"));
            }
            
            // Get or create roles
            Role adminRole = roleRepository.findByName("ROLE_ADMIN");
            Role userRole = roleRepository.findByName("ROLE_USER");
            
            if (adminRole == null) {
                adminRole = new Role("ROLE_ADMIN");
                adminRole = roleRepository.save(adminRole);
            }
            
            if (userRole == null) {
                userRole = new Role("ROLE_USER");
                userRole = roleRepository.save(userRole);
            }
            
            // Create admin user
            User adminUser = new User();
            adminUser.setUsername(adminData.getUsername().trim());
            adminUser.setFirstname(adminData.getFirstname().trim());
            adminUser.setLastname(adminData.getLastname().trim());
            adminUser.setEmail(adminData.getEmail().trim().toLowerCase());
            adminUser.setPassword(passwordEncoder.encode(adminData.getPassword()));
            adminUser.setRoles(Arrays.asList(adminRole, userRole));
            
            User createdAdmin = userRepository.save(adminUser);
            
            Map<String, Object> response = new HashMap<>();
            response.put("message", "Admin user created successfully");
            response.put("userId", createdAdmin.getId());
            response.put("username", createdAdmin.getUsername());
            response.put("email", createdAdmin.getEmail());
            
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            return ResponseEntity.status(500)
                .body(createErrorResponse("Failed to create admin: " + e.getMessage()));
        }
    }
    
    /**
     * Change admin password (requires existing admin authentication).
     */
    @PostMapping("/change-password")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> changeAdminPassword(@RequestBody PasswordChangeDTO passwordData) {
        try {
            // Get current user
            String currentUsername = org.springframework.security.core.context.SecurityContextHolder
                .getContext().getAuthentication().getName();
            
            Optional<User> currentUserOpt = userService.findByUsername(currentUsername);
            if (currentUserOpt.isEmpty()) {
                return ResponseEntity.status(401)
                    .body(createErrorResponse("User not found"));
            }
            
            User currentUser = currentUserOpt.get();
            
            // Verify current password
            if (!passwordEncoder.matches(passwordData.getCurrentPassword(), currentUser.getPassword())) {
                return ResponseEntity.badRequest()
                    .body(createErrorResponse("Current password is incorrect"));
            }
            
            // Update password
            currentUser.setPassword(passwordEncoder.encode(passwordData.getNewPassword()));
            userRepository.save(currentUser);
            
            Map<String, String> response = new HashMap<>();
            response.put("message", "Password changed successfully");
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            return ResponseEntity.status(500)
                .body(createErrorResponse("Failed to change password: " + e.getMessage()));
        }
    }
    
    private Map<String, String> createErrorResponse(String message) {
        Map<String, String> response = new HashMap<>();
        response.put("error", message);
        return response;
    }
}