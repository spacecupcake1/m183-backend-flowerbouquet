package com.bbzbl.flowerbouquet;

import java.util.Arrays;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import com.bbzbl.flowerbouquet.security.Role;
import com.bbzbl.flowerbouquet.security.RoleRepository;
import com.bbzbl.flowerbouquet.user.User;
import com.bbzbl.flowerbouquet.user.UserRepository;

/**
 * TEMPORARY VERSION with hardcoded fallback for debugging.
 * REMOVE HARDCODED CREDENTIALS BEFORE PRODUCTION!
 */
@Component
public class SecureDataInitializer implements CommandLineRunner {

    @Autowired
    private RoleRepository roleRepository;
    
    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private PasswordEncoder passwordEncoder;
    
    // Environment variables for admin credentials
    @Value("${app.admin.username:#{null}}")
    private String adminUsername;
    
    @Value("${app.admin.password:#{null}}")
    private String adminPassword;
    
    @Value("${app.admin.email:#{null}}")
    private String adminEmail;

    @Override
    public void run(String... args) throws Exception {
        System.out.println("=== Starting Secure Data Initialization (DEBUG VERSION) ===");
        
        // Debug environment variables
        System.out.println("Environment variables check:");
        System.out.println("  APP_ADMIN_USERNAME: " + (adminUsername != null ? adminUsername : "NOT SET"));
        System.out.println("  APP_ADMIN_PASSWORD: " + (adminPassword != null ? "[SET - length: " + adminPassword.length() + "]" : "NOT SET"));
        System.out.println("  APP_ADMIN_EMAIL: " + (adminEmail != null ? adminEmail : "NOT SET"));
        
        // Create default roles
        Role userRole = createRoleIfNotExists("ROLE_USER");
        Role adminRole = createRoleIfNotExists("ROLE_ADMIN");

        // Create admin user with fallback
        createAdminUserWithFallback(userRole, adminRole);
        
        System.out.println("=== Data Initialization Complete ===");
    }
    
    private Role createRoleIfNotExists(String roleName) {
        Role role = roleRepository.findByName(roleName);
        if (role == null) {
            role = new Role(roleName);
            role = roleRepository.save(role);
            System.out.println("✅ Created role: " + roleName);
        } else {
            System.out.println("✓ Role already exists: " + roleName);
        }
        return role;
    }
    
    private void createAdminUserWithFallback(Role userRole, Role adminRole) {
        // Check if any admin already exists
        Optional<User> existingAdmin = findExistingAdmin();
        if (existingAdmin.isPresent()) {
            System.out.println("✓ Admin user already exists: " + existingAdmin.get().getUsername());
            return;
        }
        
        // Try environment variables first
        if (adminUsername != null && adminPassword != null) {
            System.out.println("✅ Using admin credentials from environment variables");
            createAdminUser(adminUsername, adminPassword, adminEmail, userRole, adminRole);
            return;
        }
        
        // TEMPORARY FALLBACK - REMOVE IN PRODUCTION!
        System.out.println("⚠️ Environment variables not set, using temporary fallback credentials");
        System.out.println("⚠️ THIS IS FOR DEBUGGING ONLY - REMOVE BEFORE PRODUCTION!");
        
        String fallbackUsername = "admin";
        String fallbackPassword = "admin123";
        String fallbackEmail = "admin@temp.com";
        
        createAdminUser(fallbackUsername, fallbackPassword, fallbackEmail, userRole, adminRole);
        
        System.out.println("🔑 TEMPORARY ADMIN CREDENTIALS:");
        System.out.println("   Username: " + fallbackUsername);
        System.out.println("   Password: " + fallbackPassword);
        System.out.println("   *** CHANGE THESE CREDENTIALS IMMEDIATELY ***");
    }
    
    private void createAdminUser(String username, String password, String email, Role userRole, Role adminRole) {
        try {
            User adminUser = new User();
            adminUser.setUsername(username);
            adminUser.setFirstname("Admin");
            adminUser.setLastname("User");
            adminUser.setEmail(email != null ? email : username + "@temp.com");
            adminUser.setPassword(passwordEncoder.encode(password));
            adminUser.setRoles(Arrays.asList(adminRole, userRole));
            
            User savedAdmin = userRepository.save(adminUser);
            
            System.out.println("✅ Admin user created successfully:");
            System.out.println("   Username: " + savedAdmin.getUsername());
            System.out.println("   Email: " + savedAdmin.getEmail());
            System.out.println("   ID: " + savedAdmin.getId());
            System.out.println("   Roles: " + savedAdmin.getRoles().size());
            
            // Verify roles were saved
            savedAdmin.getRoles().forEach(role -> {
                System.out.println("   - " + role.getName());
            });
            
        } catch (Exception e) {
            System.err.println("❌ Failed to create admin user: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    private Optional<User> findExistingAdmin() {
        // Check if any user has admin role
        return userRepository.findAll().stream()
            .filter(user -> user.getRoles() != null && 
                user.getRoles().stream().anyMatch(role -> "ROLE_ADMIN".equals(role.getName())))
            .findFirst();
    }
}