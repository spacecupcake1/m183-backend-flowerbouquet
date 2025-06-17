package com.bbzbl.flowerbouquet.security;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import com.bbzbl.flowerbouquet.user.User;
import com.bbzbl.flowerbouquet.user.UserRepository;

/**
 * Data loader that initializes default users, roles, and privileges when the application starts.
 * Uses environment variables for secure credential management.
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

    // Security configuration from environment variables
    // 🚨 NO DEFAULT - Environment variable REQUIRED
    @Value("${app.security.pepper}")
    private String pepper;

    // ⚠️ NO DEFAULT for password - Environment variable REQUIRED  
    @Value("${app.admin.username:admin}")  // Username default OK
    private String adminUsername;

    @Value("${app.admin.password}")  // 🚨 NO DEFAULT - REQUIRED
    private String adminPassword;

    // ✅ Non-sensitive defaults OK
    @Value("${app.admin.email:admin@company.com}")
    private String adminEmail;

    @Value("${app.admin.firstname:System}")
    private String adminFirstname;

    @Value("${app.admin.lastname:Administrator}")
    private String adminLastname;

    // Test user with NO password default
    @Value("${app.testuser.username:testuser}")
    private String testUsername;

    @Value("${app.testuser.password:}")  // Empty default = disabled
    private String testPassword;

    @Value("${app.testuser.email:test@company.com}")
    private String testEmail;

    @Value("${app.testuser.firstname:Test}")
    private String testFirstname;

    @Value("${app.testuser.lastname:User}")
    private String testLastname;

    // Control flags
    @Value("${app.setup.create-admin:true}")
    private boolean createAdminUser;

    @Value("${app.setup.create-testuser:false}")  // Disabled by default
    private boolean createTestUser;

    @Value("${app.setup.log-credentials:false}")
    private boolean logCredentials;

    private void debugEnvironmentVariables() {
        System.out.println("=== ENVIRONMENT VARIABLES DEBUG ===");
        System.out.println("Pepper configured: " + (pepper != null && !pepper.isEmpty()));
        System.out.println("Pepper value: " + (pepper != null ? pepper.substring(0, Math.min(10, pepper.length())) + "..." : "null"));
        System.out.println("Admin username: " + adminUsername);
        System.out.println("Admin password configured: " + (adminPassword != null && !adminPassword.isEmpty()));
        System.out.println("Admin password: " + (adminPassword != null ? adminPassword.substring(0, Math.min(5, adminPassword.length())) + "..." : "null"));
        System.out.println("Create admin user: " + createAdminUser);
        System.out.println("Log credentials: " + logCredentials);
        System.out.println("=== END ENVIRONMENT VARIABLES DEBUG ===");
    }

    /**
     * Executes when the application context is refreshed (application startup).
     */
    @Override
    @Transactional
    public void onApplicationEvent(ContextRefreshedEvent event) {
        if (alreadySetup) {
            return;
        }

        debugEnvironmentVariables();

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

        // Create default users based on configuration
        if (createAdminUser) {
            createDefaultAdminUser(adminRole);
        }

        if (createTestUser) {
            createDefaultUser(userRole);
        }

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
        if (userRepository.findByUsername(adminUsername).isEmpty()) {
            User adminUser = new User();
            adminUser.setUsername(adminUsername);
            adminUser.setFirstname(adminFirstname);
            adminUser.setLastname(adminLastname);
            adminUser.setEmail(adminEmail);
            
            // Add pepper to password before encoding
            String pepperedPassword = addPepper(adminPassword);
            adminUser.setPassword(passwordEncoder.encode(pepperedPassword));
            
            adminUser.setRoles(Arrays.asList(adminRole));
            userRepository.save(adminUser);
            
            if (logCredentials) {
                System.out.println("Default admin user created:");
                System.out.println("Username: " + adminUsername);
                System.out.println("Password: " + adminPassword + " (CHANGE THIS IN PRODUCTION!)");
            } else {
                System.out.println("Default admin user created with username: " + adminUsername);
                System.out.println("Password set from configuration (check environment variables)");
            }
        }
    }

    /**
     * Creates a default regular user for testing purposes.
     */
    @Transactional
    void createDefaultUser(Role userRole) {
        if (userRepository.findByUsername(testUsername).isEmpty()) {
            User regularUser = new User();
            regularUser.setUsername(testUsername);
            regularUser.setFirstname(testFirstname);
            regularUser.setLastname(testLastname);
            regularUser.setEmail(testEmail);
            
            // Add pepper to password before encoding
            String pepperedPassword = addPepper(testPassword);
            regularUser.setPassword(passwordEncoder.encode(pepperedPassword));
            
            regularUser.setRoles(Arrays.asList(userRole));
            userRepository.save(regularUser);
            
            if (logCredentials) {
                System.out.println("Default test user created:");
                System.out.println("Username: " + testUsername);
                System.out.println("Password: " + testPassword);
            } else {
                System.out.println("Default test user created with username: " + testUsername);
                System.out.println("Password set from configuration");
            }
        }
    }

    /**
     * Add pepper to password (pepper is now from environment variable).
     */
    private String addPepper(String password) {
        return password + pepper;
    }
}