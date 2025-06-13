package com.bbzbl.flowerbouquet.security;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import com.bbzbl.flowerbouquet.user.User;
import com.bbzbl.flowerbouquet.user.UserRepository;

/**
 * Data loader that initializes default users, roles, and privileges when the application starts.
 * This ensures that the system has proper initial security setup.
 */
@Component
public class SetupDataLoader implements ApplicationListener<ContextRefreshedEvent> {

    private boolean alreadySetup = false;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PrivilegeRepository privilegeRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    /**
     * Executes when the application context is refreshed (application startup).
     */
    @Override
    @Transactional
    public void onApplicationEvent(ContextRefreshedEvent event) {
        if (alreadySetup) {
            return;
        }

        // Create privileges
        Privilege readPrivilege = createPrivilegeIfNotFound("READ_PRIVILEGE", "Read access to resources");
        Privilege writePrivilege = createPrivilegeIfNotFound("WRITE_PRIVILEGE", "Write access to resources");
        Privilege deletePrivilege = createPrivilegeIfNotFound("DELETE_PRIVILEGE", "Delete access to resources");
        
        // User-specific privileges
        Privilege readUsersPrivilege = createPrivilegeIfNotFound("READ_USERS", "Read user information");
        Privilege writeUsersPrivilege = createPrivilegeIfNotFound("WRITE_USERS", "Create and update users");
        Privilege deleteUsersPrivilege = createPrivilegeIfNotFound("DELETE_USERS", "Delete users");
        
        // Admin privileges
        Privilege adminPrivilege = createPrivilegeIfNotFound("ADMIN_PRIVILEGE", "Full administrative access");

        // Create roles with privileges
        List<Privilege> adminPrivileges = Arrays.asList(
            readPrivilege, writePrivilege, deletePrivilege,
            readUsersPrivilege, writeUsersPrivilege, deleteUsersPrivilege,
            adminPrivilege
        );
        Role adminRole = createRoleIfNotFound("ROLE_ADMIN", adminPrivileges);

        List<Privilege> userPrivileges = Arrays.asList(readPrivilege, readUsersPrivilege);
        Role userRole = createRoleIfNotFound("ROLE_USER", userPrivileges);

        // Create moderator role (optional)
        List<Privilege> moderatorPrivileges = Arrays.asList(
            readPrivilege, writePrivilege, readUsersPrivilege, writeUsersPrivilege
        );
        Role moderatorRole = createRoleIfNotFound("ROLE_MODERATOR", moderatorPrivileges);

        // Create default admin user
        createDefaultAdminUser(adminRole);

        // Create default regular user
        createDefaultUser(userRole);

        alreadySetup = true;
    }

    /**
     * Creates a privilege if it doesn't already exist.
     */
    @Transactional
    Privilege createPrivilegeIfNotFound(String name, String description) {
        Privilege privilege = privilegeRepository.findByName(name);
        if (privilege == null) {
            privilege = new Privilege(name, description);
            privilegeRepository.save(privilege);
        }
        return privilege;
    }

    /**
     * Creates a role if it doesn't already exist.
     * Removed setDescription call since Role entity might not have this field.
     */
    @Transactional
    Role createRoleIfNotFound(String name, Collection<Privilege> privileges) {
        Role role = roleRepository.findByName(name);
        if (role == null) {
            role = new Role(name);
            role.setPrivileges(privileges);
            roleRepository.save(role);
        } else {
            // Update privileges if role exists but privileges have changed
            role.setPrivileges(privileges);
            roleRepository.save(role);
        }
        return role;
    }

    /**
     * Creates the default admin user if it doesn't exist.
     */
    @Transactional
    void createDefaultAdminUser(Role adminRole) {
        if (userRepository.findByUsername("admin").isEmpty()) {
            User adminUser = new User();
            adminUser.setUsername("admin");
            adminUser.setFirstname("System");
            adminUser.setLastname("Administrator");
            adminUser.setEmail("admin@flowerbouquet.com");
            
            // Add pepper to password before encoding (same as in AuthController)
            String password = "Admin123!@#";
            String pepperedPassword = addPepper(password);
            adminUser.setPassword(passwordEncoder.encode(pepperedPassword));
            
            adminUser.setRoles(Arrays.asList(adminRole));
            userRepository.save(adminUser);
            
            System.out.println("Default admin user created:");
            System.out.println("Username: admin");
            System.out.println("Password: Admin123!@# (CHANGE THIS IN PRODUCTION!)");
        }
    }

    /**
     * Creates a default regular user for testing purposes.
     */
    @Transactional
    void createDefaultUser(Role userRole) {
        if (userRepository.findByUsername("user").isEmpty()) {
            User regularUser = new User();
            regularUser.setUsername("user");
            regularUser.setFirstname("Test");
            regularUser.setLastname("User");
            regularUser.setEmail("user@flowerbouquet.com");
            
            // Add pepper to password before encoding
            String password = "User123!";
            String pepperedPassword = addPepper(password);
            regularUser.setPassword(passwordEncoder.encode(pepperedPassword));
            
            regularUser.setRoles(Arrays.asList(userRole));
            userRepository.save(regularUser);
            
            System.out.println("Default test user created:");
            System.out.println("Username: user");
            System.out.println("Password: User123!");
        }
    }

    /**
     * Add pepper to password (must match the pepper used in AuthController).
     */
    private String addPepper(String password) {
        // This should match the pepper in AuthController
        // In production, store this in environment variables or secure configuration
        final String PEPPER = "MySecretPepperKey2024!@#$%^&*()";
        return password + PEPPER;
    }
}