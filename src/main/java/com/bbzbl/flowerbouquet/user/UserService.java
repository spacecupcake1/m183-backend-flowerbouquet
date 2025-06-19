package com.bbzbl.flowerbouquet.user;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.bbzbl.flowerbouquet.security.Role;
import com.bbzbl.flowerbouquet.security.RoleRepository;

@Service
@Transactional
public class UserService {

    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private RoleRepository roleRepository;
    
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Value("${app.security.pepper:MySecretPepperKey2024!@#$%^&*()}")
    private String pepper;

    public List<User> getAllUsers() {
        return userRepository.findAllWithRoles();
    }

    public Optional<User> getUserById(Long id) {
        return userRepository.findByIdWithRoles(id);
    }

    public User createUser(UserRegistrationDTO registrationDTO) {
        
        // Validate password strength
        validatePasswordStrength(registrationDTO.getPassword());
        
        // Create new user entity
        User user = new User();
        user.setUsername(registrationDTO.getUsername());
        user.setFirstname(registrationDTO.getFirstname());
        user.setLastname(registrationDTO.getLastname());
        user.setEmail(registrationDTO.getEmail());
        
        // Hash password with pepper + BCrypt
        String hashedPassword = hashPasswordWithPepper(registrationDTO.getPassword());
        user.setPassword(hashedPassword);
        
        // Set default user role - FIXED: Proper Optional handling
        Role userRole = roleRepository.findByName("ROLE_USER");
        if (userRole == null) {
            throw new RuntimeException("Error: Role ROLE_USER is not found.");
        }
        user.getRoles().add(userRole);
        
        // Set timestamps and defaults
        user.setCreatedAt(LocalDateTime.now());
        user.setUpdatedAt(LocalDateTime.now());
        user.setEnabled(true);
        user.setAccountNonExpired(true);
        user.setAccountNonLocked(true);
        user.setCredentialsNonExpired(true);
        user.setFailedLoginAttempts(0);
        
        return userRepository.save(user);
    }

    public User saveUser(User user) {
        // For backward compatibility with existing code
        // This method should only be used for non-registration scenarios
        user.setUpdatedAt(LocalDateTime.now());
        if (user.getCreatedAt() == null) {
            user.setCreatedAt(LocalDateTime.now());
        }
        return userRepository.save(user);
    }

    /**
     * Update user
     */
    public User updateUser(Long id, User userDetails) {
        User user = userRepository.findById(id)
            .orElseThrow(() -> new RuntimeException("User not found with id: " + id));

        user.setUsername(userDetails.getUsername());
        user.setFirstname(userDetails.getFirstname());
        user.setLastname(userDetails.getLastname());
        user.setEmail(userDetails.getEmail());
        user.setUpdatedAt(LocalDateTime.now());

        return userRepository.save(user);
    }

    /**
     * Delete user
     */
    public void deleteUser(Long id) {
        User user = userRepository.findById(id)
            .orElseThrow(() -> new RuntimeException("User not found with id: " + id));
        userRepository.delete(user);
    }

    /**
     * Find user by username
     */
    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    /**
     * Check if user is admin
     */
    public boolean isAdmin(User user) {
        return user.getRoles().stream()
            .anyMatch(role -> role.getName().equals("ROLE_ADMIN"));
    }

    /**
     * Check if user exists by username or email
     */
    public boolean existsByUsernameOrEmail(String username, String email) {
        return userRepository.existsByUsernameOrEmail(username, email);
    }

    /**
     * Add role to user
     */
    public void addRoleToUser(Long userId, String roleName) {
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new RuntimeException("User not found"));
        
        Role role = roleRepository.findByName(roleName);
        if (role == null) {
            throw new RuntimeException("Role not found: " + roleName);
        }
        
        user.getRoles().add(role);
        userRepository.save(user);
    }

    // ========== PASSWORD SECURITY METHODS ==========

    /**
     * Hash password with pepper + BCrypt
     */
    private String hashPasswordWithPepper(String rawPassword) {
        String pepperedPassword = rawPassword + pepper;
        return passwordEncoder.encode(pepperedPassword);
    }
    
    /**
     * Verify password with pepper + BCrypt
     */
    public boolean verifyPassword(String rawPassword, String encodedPassword) {
        String pepperedPassword = rawPassword + pepper;
        return passwordEncoder.matches(pepperedPassword, encodedPassword);
    }
    
    /**
     * Password strength validation
     */
    private void validatePasswordStrength(String password) {
        if (password == null || password.length() < 8) {
            throw new IllegalArgumentException("Password must be at least 8 characters long");
        }
        
        if (password.length() > 100) {
            throw new IllegalArgumentException("Password cannot exceed 100 characters");
        }
        
        if (!password.matches(".*[A-Z].*")) {
            throw new IllegalArgumentException("Password must contain at least one uppercase letter");
        }
        
        if (!password.matches(".*[a-z].*")) {
            throw new IllegalArgumentException("Password must contain at least one lowercase letter");
        }
        
        if (!password.matches(".*[0-9].*")) {
            throw new IllegalArgumentException("Password must contain at least one number");
        }
        
        if (!password.matches(".*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>\\/?].*")) {
            throw new IllegalArgumentException("Password must contain at least one special character");
        }
    }
      
    /**
     * Update user password securely
     */
    public User updateUserPassword(Long userId, String oldPassword, String newPassword) {
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new RuntimeException("User not found"));
        
        // Verify old password
        if (!verifyPassword(oldPassword, user.getPassword())) {
            throw new IllegalArgumentException("Current password is incorrect");
        }
        
        // Validate new password strength
        validatePasswordStrength(newPassword);
        
        // Hash and set new password
        user.setPassword(hashPasswordWithPepper(newPassword));
        user.setUpdatedAt(LocalDateTime.now());
        user.setCredentialsNonExpired(true); // Reset expiry if needed
        
        return userRepository.save(user);
    }

    /**
     * Save or update user entity
     */
    public User save(User user) {
        return userRepository.save(user);
    }

    /**
     * Update user's last login time
     */
    public void updateLastLogin(Long userId) {
        userRepository.findById(userId).ifPresent(user -> {
            user.setLastLogin(java.time.LocalDateTime.now());
            userRepository.save(user);
        });
    }

    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    public boolean existsByUsername(String username) {
        return userRepository.existsByUsername(username);
    }

    public boolean existsByEmail(String email) {
        return userRepository.existsByEmail(email);
    }

    public boolean hasRole(User user, String roleName) {
        if (user.getRoles() == null) return false;
        return user.getRoles().stream()
                .anyMatch(role -> role.getName().equals(roleName));
    }

    public boolean isModerator(User user) {
        return hasRole(user, "ROLE_MODERATOR");
    }

    public void removeRoleFromUser(Long userId, String roleName) {
        User user = getUserById(userId)
            .orElseThrow(() -> new RuntimeException("User not found"));
        
        user.getRoles().removeIf(role -> role.getName().equals(roleName));
        userRepository.save(user);
    }

    public void clearUserSession(String username) {
        // Implementation for clearing user sessions
        // This would integrate with session registry
    }
}