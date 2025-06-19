package com.bbzbl.flowerbouquet.user;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    
    // ========== EXISTING METHODS (keep what you have) ==========
    Optional<User> findByUsername(String username);
    Optional<User> findByEmail(String email);
    
    // ========== ADD THESE MISSING METHODS ==========
    
    /**
     * Check if a user exists with the given username
     */
    boolean existsByUsername(String username);
    
    /**
     * Check if a user exists with the given email
     */
    boolean existsByEmail(String email);
    
    /**
     * Find user by username or email (useful for login)
     */
    @Query("SELECT u FROM User u WHERE u.username = :usernameOrEmail OR u.email = :usernameOrEmail")
    Optional<User> findByUsernameOrEmail(@Param("usernameOrEmail") String usernameOrEmail);
    
    /**
     * Check if username or email already exists (for registration validation)
     */
    @Query("SELECT CASE WHEN COUNT(u) > 0 THEN true ELSE false END FROM User u WHERE u.username = :username OR u.email = :email")
    boolean existsByUsernameOrEmail(@Param("username") String username, @Param("email") String email);
    
    /**
     * Find all users with a specific role
     */
    @Query("SELECT u FROM User u JOIN u.roles r WHERE r.name = :roleName")
    List<User> findByRoleName(@Param("roleName") String roleName);
    
    /**
     * Find all admin users
     */
    @Query("SELECT u FROM User u JOIN u.roles r WHERE r.name = 'ROLE_ADMIN'")
    List<User> findAllAdmins();
    
    /**
     * Find all users with their roles (fix for findAllWithRoles)
     */
    @Query("SELECT DISTINCT u FROM User u LEFT JOIN FETCH u.roles")
    List<User> findAllWithRoles();
    
    /**
     * Find user by ID with roles (fix for findByIdWithRoles)
     */
    @Query("SELECT u FROM User u LEFT JOIN FETCH u.roles WHERE u.id = :id")
    Optional<User> findByIdWithRoles(@Param("id") Long id);
    
    /**
     * Count users with failed login attempts
     */
    @Query("SELECT COUNT(u) FROM User u WHERE u.failedLoginAttempts >= :attempts")
    long countUsersWithFailedAttempts(@Param("attempts") int attempts);
    
    /**
     * Find users with account locked
     */
    @Query("SELECT u FROM User u WHERE u.accountNonLocked = false OR u.accountLockedUntil > CURRENT_TIMESTAMP")
    List<User> findLockedUsers();
}