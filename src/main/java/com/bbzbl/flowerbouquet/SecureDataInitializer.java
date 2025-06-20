package com.bbzbl.flowerbouquet;

import java.util.Arrays;
import java.util.HashSet;
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
 * PRODUCTION SECURE VERSION - NO CREDENTIAL LOGGING
 */
@Component
public class SecureDataInitializer implements CommandLineRunner {

    @Autowired
    private RoleRepository roleRepository;
    
    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private PasswordEncoder passwordEncoder;
    
    @Value("${app.admin.username:#{null}}")
    private String adminUsername;
    
    @Value("${app.admin.password:#{null}}")
    private String adminPassword;
    
    @Value("${app.admin.email:#{null}}")
    private String adminEmail;
    
    @Value("${app.admin.firstname:Admin}")
    private String adminFirstname;
    
    @Value("${app.admin.lastname:User}")
    private String adminLastname;
    
    @Value("${app.create.admin:true}")
    private boolean createAdmin;

    @Override
    public void run(String... args) throws Exception {
        System.out.println("=== Starting Data Initialization ===");
        
        // Create default roles
        Role userRole = createRoleIfNotExists("ROLE_USER");
        Role adminRole = createRoleIfNotExists("ROLE_ADMIN");

        // Create or fix admin user
        if (createAdmin) {
            createOrFixAdminUser(userRole, adminRole);
        }
        
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
    
    private void createOrFixAdminUser(Role userRole, Role adminRole) {
        if (adminUsername == null || adminPassword == null) {
            System.out.println("⚠️ Admin credentials not provided via environment variables");
            return;
        }
        
        try {
            Optional<User> existingAdmin = userRepository.findByUsername(adminUsername);
            
            if (existingAdmin.isPresent()) {
                // Fix existing admin if password is not BCrypt encoded
                User admin = existingAdmin.get();
                
                // Check if password is properly BCrypt encoded
                if (!admin.getPassword().startsWith("$2a$") && !admin.getPassword().startsWith("$2b$")) {
                    System.out.println("🔧 Fixing admin password encoding...");
                    admin.setPassword(passwordEncoder.encode(adminPassword));
                    userRepository.save(admin);
                    System.out.println("✅ Admin password encoding fixed");
                } else {
                    System.out.println("✓ Admin user already exists with proper encoding");
                }
            } else {
                // Create new admin user
                User adminUser = new User();
                adminUser.setUsername(adminUsername.trim());
                adminUser.setFirstname(adminFirstname);
                adminUser.setLastname(adminLastname);
                adminUser.setEmail(adminEmail != null ? adminEmail : adminUsername + "@company.com");
                adminUser.setPassword(passwordEncoder.encode(adminPassword));
               adminUser.setRoles(new HashSet<>(Arrays.asList(adminRole, userRole)));
                
                User savedAdmin = userRepository.save(adminUser);
                System.out.println("✅ Admin user created successfully");
                System.out.println("   Username: " + savedAdmin.getUsername());
                System.out.println("   Email: " + savedAdmin.getEmail());
            }
            
        } catch (Exception e) {
            System.err.println("❌ Failed to create/fix admin user: " + e.getMessage());
        }
    }
}