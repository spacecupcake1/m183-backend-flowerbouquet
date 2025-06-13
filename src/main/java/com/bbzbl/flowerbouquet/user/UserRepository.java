package com.bbzbl.flowerbouquet.user;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

/**
 * Repository interface for User entity data access operations.
 * Provides CRUD operations and custom query methods with security considerations.
 */
@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    /**
     * Find user by username (case-insensitive).
     * Uses parameterized query to prevent SQL injection.
     * 
     * @param username the username to search for
     * @return Optional containing the user if found
     */
    @Query("SELECT u FROM User u WHERE LOWER(u.username) = LOWER(:username)")
    Optional<User> findByUsername(@Param("username") String username);

    /**
     * Find user by email (case-insensitive).
     * Uses parameterized query to prevent SQL injection.
     * 
     * @param email the email to search for
     * @return Optional containing the user if found
     */
    @Query("SELECT u FROM User u WHERE LOWER(u.email) = LOWER(:email)")
    Optional<User> findByEmail(@Param("email") String email);

    /**
     * Check if username exists (case-insensitive).
     * Uses parameterized query to prevent SQL injection.
     * 
     * @param username the username to check
     * @return true if username exists, false otherwise
     */
    @Query("SELECT COUNT(u) > 0 FROM User u WHERE LOWER(u.username) = LOWER(:username)")
    boolean existsByUsernameIgnoreCase(@Param("username") String username);

    /**
     * Check if email exists (case-insensitive).
     * Uses parameterized query to prevent SQL injection.
     * 
     * @param email the email to check
     * @return true if email exists, false otherwise
     */
    @Query("SELECT COUNT(u) > 0 FROM User u WHERE LOWER(u.email) = LOWER(:email)")
    boolean existsByEmailIgnoreCase(@Param("email") String email);

    /**
     * Find users by role name.
     * Uses JOIN to fetch users with specific role.
     * 
     * @param roleName the role name to search for
     * @return list of users with the specified role
     */
    @Query("SELECT DISTINCT u FROM User u JOIN u.roles r WHERE r.name = :roleName")
    java.util.List<User> findByRoleName(@Param("roleName") String roleName);

    /**
     * Find all admin users.
     * Convenience method to find users with ROLE_ADMIN.
     * 
     * @return list of admin users
     */
    @Query("SELECT DISTINCT u FROM User u JOIN u.roles r WHERE r.name = 'ROLE_ADMIN'")
    java.util.List<User> findAllAdmins();

    /**
     * Check if user has specific role.
     * 
     * @param userId the user ID
     * @param roleName the role name to check
     * @return true if user has the role, false otherwise
     */
    @Query("SELECT COUNT(u) > 0 FROM User u JOIN u.roles r WHERE u.id = :userId AND r.name = :roleName")
    boolean hasRole(@Param("userId") Long userId, @Param("roleName") String roleName);

    /**
     * Count users by role.
     * 
     * @param roleName the role name
     * @return number of users with the specified role
     */
    @Query("SELECT COUNT(DISTINCT u) FROM User u JOIN u.roles r WHERE r.name = :roleName")
    long countByRole(@Param("roleName") String roleName);

    /**
     * Find users with multiple roles using IN clause.
     * Secure parameterized query to prevent SQL injection.
     * 
     * @param roleNames list of role names
     * @return list of users with any of the specified roles
     */
    @Query("SELECT DISTINCT u FROM User u JOIN u.roles r WHERE r.name IN :roleNames")
    java.util.List<User> findByRoleNames(@Param("roleNames") java.util.List<String> roleNames);

    /**
     * Find user by ID with roles eagerly loaded.
     * Prevents N+1 query problem.
     * 
     * @param id the user ID
     * @return Optional containing the user with roles if found
     */
    @Query("SELECT u FROM User u LEFT JOIN FETCH u.roles WHERE u.id = :id")
    Optional<User> findByIdWithRoles(@Param("id") Long id);

    /**
     * Find all users with roles eagerly loaded.
     * Prevents N+1 query problem for bulk operations.
     * 
     * @return list of all users with roles loaded
     */
    @Query("SELECT DISTINCT u FROM User u LEFT JOIN FETCH u.roles")
    java.util.List<User> findAllWithRoles();
}