package com.bbzbl.flowerbouquet.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import com.bbzbl.flowerbouquet.security.Role;
import com.bbzbl.flowerbouquet.security.RoleRepository;
import com.bbzbl.flowerbouquet.user.User;
import com.bbzbl.flowerbouquet.user.UserRegistrationDTO;
import com.bbzbl.flowerbouquet.user.UserRepository;
import com.bbzbl.flowerbouquet.user.UserService;

@Component
public class DataLoader implements CommandLineRunner {

    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private RoleRepository roleRepository;
    
    @Autowired
    private UserService userService;

    @Override
    public void run(String... args) throws Exception {
        createRoleIfNotExists("ROLE_USER");
        createRoleIfNotExists("ROLE_ADMIN");
        createAdminUserIfNotExists();
        
        System.out.println("=== ADMIN CREATED ===");
        System.out.println("Username: admin");
        System.out.println("Password: Admin123!");
    }
    
    /**
     * FIXED: Handle Role return type (not Optional<Role>)
     */
    private void createRoleIfNotExists(String roleName) {
        Role existingRole = roleRepository.findByName(roleName);
        if (existingRole == null) {
            Role role = new Role();
            role.setName(roleName);
            roleRepository.save(role);
            System.out.println("Created role: " + roleName);
        }
    }
    
    /**
     * FIXED: Handle Role return type (not Optional<Role>)
     */
    private void createAdminUserIfNotExists() {
        // Check if admin user exists (this should return Optional<User>)
        if (userRepository.findByUsername("admin").isEmpty()) {
            try {
                UserRegistrationDTO adminDto = new UserRegistrationDTO();
                adminDto.setUsername("admin");
                adminDto.setFirstname("Admin");
                adminDto.setLastname("User");
                adminDto.setEmail("admin@flowerbouquet.com");
                adminDto.setPassword("Admin123!");
                
                User adminUser = userService.createUser(adminDto);
                
                // FIXED: Handle Role return type (not Optional<Role>)
                Role adminRole = roleRepository.findByName("ROLE_ADMIN");
                if (adminRole != null) {
                    adminUser.getRoles().add(adminRole);
                    userRepository.save(adminUser);
                    System.out.println("✅ ADMIN USER CREATED!");
                } else {
                    System.err.println("❌ ROLE_ADMIN not found!");
                }
                
            } catch (Exception e) {
                System.err.println("❌ Failed to create admin: " + e.getMessage());
                e.printStackTrace();
            }
        } else {
            System.out.println("ℹ️  Admin user already exists");
        }
    }
}