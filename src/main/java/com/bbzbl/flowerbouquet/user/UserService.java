package com.bbzbl.flowerbouquet.user;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.bbzbl.flowerbouquet.security.Role;
import com.bbzbl.flowerbouquet.security.RoleRepository;

@Service
public class UserService {

    private final UserRepository userRepo;
    private final RoleRepository roleRepository;

    @Autowired
    public UserService(UserRepository userRepo, RoleRepository roleRepository) {
        this.userRepo = userRepo;
        this.roleRepository = roleRepository;
    }

    public List<User> getAllUsers() {
        return userRepo.findAll();
    }

    public Optional<User> getUserById(Long id) {
        return userRepo.findById(id);
    }

    public User createUser(User user) {
        // Assign ROLE_USER to new registrations
        Role userRole = roleRepository.findByName("ROLE_USER");
        if (userRole != null) {
            user.setRoles(Arrays.asList(userRole));
        } else {
            // Create default role if it doesn't exist
            userRole = new Role("ROLE_USER");
            userRole = roleRepository.save(userRole);
            user.setRoles(Arrays.asList(userRole));
        }
        return userRepo.save(user);
    }

    public Optional<User> findByUsername(String username) {
        return userRepo.findByUsername(username);
    }

    public boolean existsByUsername(String username) {
        return userRepo.findByUsername(username).isPresent();
    }

    public boolean existsByEmail(String email) {
        return userRepo.findByEmail(email).isPresent();
    }

    public boolean hasRole(User user, String roleName) {
        if (user.getRoles() == null) return false;
        return user.getRoles().stream()
                .anyMatch(role -> role.getName().equals(roleName));
    }

    public boolean isAdmin(User user) {
        return hasRole(user, "ROLE_ADMIN");
    }
}