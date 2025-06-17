package com.bbzbl.flowerbouquet.user;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.bbzbl.flowerbouquet.security.InputValidationService;
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
    
    @Autowired
    private InputValidationService inputValidationService;

    public List<User> getAllUsers() {
        return userRepository.findAllWithRoles();
    }

    public Optional<User> getUserById(Long id) {
        return userRepository.findByIdWithRoles(id);
    }

    public User createUser(User user) {
        // Validate inputs
        if (!inputValidationService.isValidUsername(user.getUsername())) {
            throw new IllegalArgumentException("Invalid username format");
        }
        if (!inputValidationService.isValidEmail(user.getEmail())) {
            throw new IllegalArgumentException("Invalid email format");
        }

        // Check for existing users
        if (existsByUsername(user.getUsername())) {
            throw new IllegalArgumentException("Username already exists");
        }
        if (existsByEmail(user.getEmail())) {
            throw new IllegalArgumentException("Email already exists");
        }

        // Assign default role if no roles specified
        if (user.getRoles() == null || user.getRoles().isEmpty()) {
            Role userRole = roleRepository.findByName("ROLE_USER");
            if (userRole != null) {
                user.setRoles(Arrays.asList(userRole));
            }
        }

        return userRepository.save(user);
    }

    public User updateUser(Long id, User userDetails) {
        return userRepository.findById(id)
            .map(user -> {
                // Validate inputs
                if (userDetails.getFirstname() != null) {
                    if (!inputValidationService.isValidName(userDetails.getFirstname())) {
                        throw new IllegalArgumentException("Invalid firstname format");
                    }
                    user.setFirstname(userDetails.getFirstname());
                }
                if (userDetails.getLastname() != null) {
                    if (!inputValidationService.isValidName(userDetails.getLastname())) {
                        throw new IllegalArgumentException("Invalid lastname format");
                    }
                    user.setLastname(userDetails.getLastname());
                }
                if (userDetails.getEmail() != null) {
                    if (!inputValidationService.isValidEmail(userDetails.getEmail())) {
                        throw new IllegalArgumentException("Invalid email format");
                    }
                    user.setEmail(userDetails.getEmail());
                }
                return userRepository.save(user);
            })
            .orElseThrow(() -> new RuntimeException("User not found"));
    }

    public void deleteUser(Long id) {
        userRepository.deleteById(id);
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

    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    public boolean existsByUsername(String username) {
        return userRepository.existsByUsernameIgnoreCase(username);
    }

    public boolean existsByEmail(String email) {
        return userRepository.existsByEmailIgnoreCase(email);
    }

    public boolean hasRole(User user, String roleName) {
        if (user.getRoles() == null) return false;
        return user.getRoles().stream()
                .anyMatch(role -> role.getName().equals(roleName));
    }

    public boolean isAdmin(User user) {
        return hasRole(user, "ROLE_ADMIN");
    }

    public boolean isModerator(User user) {
        return hasRole(user, "ROLE_MODERATOR");
    }

    public void addRoleToUser(Long userId, String roleName) {
        User user = getUserById(userId)
            .orElseThrow(() -> new RuntimeException("User not found"));
        Role role = roleRepository.findByName(roleName);
        if (role == null) {
            throw new RuntimeException("Role not found");
        }
        
        if (!hasRole(user, roleName)) {
            user.getRoles().add(role);
            userRepository.save(user);
        }
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