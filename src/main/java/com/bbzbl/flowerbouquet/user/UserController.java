package com.bbzbl.flowerbouquet.user;

import java.security.Principal;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/users")
public class UserController {

    @Autowired
    private UserService userService;

    /**
     * Get all users - Admin only
     */
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping
    public ResponseEntity<List<User>> getAllUsers() {
        List<User> users = userService.getAllUsers();
        return ResponseEntity.ok(users);
    }

    /**
     * Get user by ID - Admin or the user themselves
     */
    @PreAuthorize("hasRole('ADMIN') or @userService.getUserById(#id).orElse(null)?.username == authentication.name")
    @GetMapping("/{id}")
    public ResponseEntity<User> getUserById(@PathVariable Long id) {
        return userService.getUserById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    /**
     * Update user - Admin or the user themselves
     */
    @PreAuthorize("hasRole('ADMIN') or @userService.getUserById(#id).orElse(null)?.username == authentication.name")
    @PutMapping("/{id}")
    public ResponseEntity<User> updateUser(@PathVariable Long id, @RequestBody User userDetails) {
        try {
            User updatedUser = userService.updateUser(id, userDetails);
            return ResponseEntity.ok(updatedUser);
        } catch (RuntimeException e) {
            return ResponseEntity.notFound().build();
        }
    }

    /**
     * Delete user - Admin only
     */
    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping("/{id}")
    public ResponseEntity<Map<String, String>> deleteUser(@PathVariable Long id) {
        try {
            userService.deleteUser(id);
            return ResponseEntity.ok(Map.of("message", "User deleted successfully"));
        } catch (Exception e) {
            return ResponseEntity.notFound().build();
        }
    }

    /**
     * Check if user is admin
     */
    @GetMapping("/{id}/is-admin")
    public ResponseEntity<Map<String, Boolean>> isUserAdmin(@PathVariable Long id, Principal principal) {
        // Only admin or the user themselves can check admin status
        if (principal == null) {
            return ResponseEntity.status(401).build();
        }

        User currentUser = userService.findByUsername(principal.getName()).orElse(null);
        if (currentUser == null) {
            return ResponseEntity.status(401).build();
        }

        // Allow if current user is admin or checking their own status
        if (!userService.isAdmin(currentUser) && !currentUser.getId().equals(id)) {
            return ResponseEntity.status(403).build();
        }

        return userService.getUserById(id)
                .map(user -> ResponseEntity.ok(Map.of("isAdmin", userService.isAdmin(user))))
                .orElse(ResponseEntity.notFound().build());
    }

    /**
     * Add role to user - Admin only
     */
    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping("/{id}/roles/{roleName}")
    public ResponseEntity<Map<String, String>> addRoleToUser(@PathVariable Long id, @PathVariable String roleName) {
        try {
            userService.addRoleToUser(id, roleName);
            return ResponseEntity.ok(Map.of("message", "Role added successfully"));
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * Remove role from user - Admin only
     */
    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping("/{id}/roles/{roleName}")
    public ResponseEntity<Map<String, String>> removeRoleFromUser(@PathVariable Long id, @PathVariable String roleName) {
        try {
            userService.removeRoleFromUser(id, roleName);
            return ResponseEntity.ok(Map.of("message", "Role removed successfully"));
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * Get current user profile
     */
    @GetMapping("/profile")
    public ResponseEntity<User> getCurrentUserProfile(Principal principal) {
        if (principal == null) {
            return ResponseEntity.status(401).build();
        }

        return userService.findByUsername(principal.getName())
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    /**
     * Update current user profile
     */
    @PutMapping("/profile")
    public ResponseEntity<User> updateCurrentUserProfile(@RequestBody User userDetails, Principal principal) {
        if (principal == null) {
            return ResponseEntity.status(401).build();
        }

        User currentUser = userService.findByUsername(principal.getName()).orElse(null);
        if (currentUser == null) {
            return ResponseEntity.status(401).build();
        }

        try {
            User updatedUser = userService.updateUser(currentUser.getId(), userDetails);
            return ResponseEntity.ok(updatedUser);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().build();
        }
    }
}