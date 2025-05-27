package com.bbzbl.flowerbouquet.user;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.bbzbl.flowerbouquet.security.Role;
import com.bbzbl.flowerbouquet.security.RoleRepository;

/**
 * Service class for managing User entities.
 */
@Service
public class UserService {

    private final UserRepository userRepo;
    private final RoleRepository roleRepository;

    /**
     * Constructor for UserService.
     *
     * @param userRepo the UserRepository to use
     * @param roleRepository the RoleRepository to use
     */
    @Autowired
    public UserService(UserRepository userRepo, RoleRepository roleRepository) {
        this.userRepo = userRepo;
        this.roleRepository = roleRepository;
    }

    /**
     * Get all users.
     *
     * @return a list of all users
     */
    public List<User> getAllUsers() {
        return userRepo.findAll();
    }

    /**
     * Get a user by ID.
     *
     * @param id the ID of the user to retrieve
     * @return an Optional containing the user if found, or empty if not found
     */
    public Optional<User> getUserById(Long id) {
        return userRepo.findById(id);
    }

    /**
     * Create a new user with ROLE_USER assigned automatically.
     *
     * @param user the user to create
     * @return the created user
     */
    public User createUser(User user) {
        // Automatically assign ROLE_USER to new registrations
        Role userRole = roleRepository.findByName("ROLE_USER");
        if (userRole != null) {
            user.setRoles(Arrays.asList(userRole));
        }
        return userRepo.save(user);
    }

    /**
     * Find user by username.
     *
     * @param username the username to search for
     * @return an Optional containing the user if found, or empty if not found
     */
    public Optional<User> findByUsername(String username) {
        return userRepo.findByUsername(username);
    }

    /**
     * Check if user has a specific role.
     *
     * @param user the user to check
     * @param roleName the role name to check for
     * @return true if user has the role, false otherwise
     */
    public boolean hasRole(User user, String roleName) {
        return user.getRoles().stream()
                .anyMatch(role -> role.getName().equals(roleName));
    }

    /**
     * Check if user is admin.
     *
     * @param user the user to check
     * @return true if user is admin, false otherwise
     */
    public boolean isAdmin(User user) {
        return hasRole(user, "ROLE_ADMIN");
    }
}