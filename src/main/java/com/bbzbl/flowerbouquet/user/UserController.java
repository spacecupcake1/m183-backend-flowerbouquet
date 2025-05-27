package com.bbzbl.flowerbouquet.user;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST controller for managing User entities.
 */
@RestController
@CrossOrigin(origins = "http://localhost:4200")
@RequestMapping("/api/users")
public class UserController {

    @Autowired
    private UserService userService;

    /**
     * Get all users.
     *
     * @return a list of all users
     */
    @GetMapping("")
    public List<User> getAllUsers() {
        return userService.getAllUsers();
    }

    /**
     * Get a user by ID.
     *
     * @param id the ID of the user to retrieve
     * @return the user with the given ID, or a 404 Not Found response if not found
     */
    @GetMapping("/{id}")
    public ResponseEntity<User> getUserById(@PathVariable Long id) {
        Optional<User> user = userService.getUserById(id);
        return user.map(ResponseEntity::ok)
                   .orElseGet(() -> ResponseEntity.notFound().build());
    }

    /**
     * Create a new user (register).
     *
     * @param user the user to create
     * @return the created user
     */
    @PostMapping
    public ResponseEntity<User> createUser(@RequestBody User user) {
        User createdUser = userService.createUser(user);
        return ResponseEntity.ok(createdUser);
    }
    
    /**
     * User login endpoint.
     *
     * @param loginRequest the login credentials
     * @return login response with user info and roles
     */
    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody User loginRequest) {
        Optional<User> user = userService.findByUsername(loginRequest.getUsername());

        Map<String, Object> response = new HashMap<>();
        if (user.isPresent() && user.get().getPassword().equals(loginRequest.getPassword())) {
            User foundUser = user.get();
            
            // Basic user info
            response.put("message", "Login successful");
            response.put("userId", foundUser.getId());
            response.put("username", foundUser.getUsername());
            response.put("firstname", foundUser.getFirstname());
            response.put("lastname", foundUser.getLastname());
            response.put("email", foundUser.getEmail());
            
            // Role information
            List<String> roleNames = foundUser.getRoles().stream()
                    .map(role -> role.getName())
                    .collect(Collectors.toList());
            response.put("roles", roleNames);
            response.put("isAdmin", userService.isAdmin(foundUser));
            
            return ResponseEntity.ok(response);
        } else {
            response.put("message", "Invalid username or password");
            return ResponseEntity.status(401).body(response);
        }
    }

    /**
     * Check if a user has admin privileges.
     *
     * @param id the user ID to check
     * @return response indicating if user is admin
     */
    @GetMapping("/{id}/is-admin")
    public ResponseEntity<Map<String, Boolean>> isUserAdmin(@PathVariable Long id) {
        Optional<User> user = userService.getUserById(id);
        
        if (user.isPresent()) {
            Map<String, Boolean> response = new HashMap<>();
            response.put("isAdmin", userService.isAdmin(user.get()));
            return ResponseEntity.ok(response);
        } else {
            return ResponseEntity.notFound().build();
        }
    }
}