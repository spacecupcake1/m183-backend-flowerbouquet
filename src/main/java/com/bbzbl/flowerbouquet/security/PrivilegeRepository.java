package com.bbzbl.flowerbouquet.security;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

/**
 * Repository interface for Privilege entity data access operations.
 * Provides CRUD operations and custom query methods for privilege management.
 */
@Repository
public interface PrivilegeRepository extends JpaRepository<Privilege, Long> {

    /**
     * Find privilege by name.
     * Uses parameterized query to prevent SQL injection.
     * 
     * @param name the privilege name to search for
     * @return the privilege if found, null otherwise
     */
    @Query("SELECT p FROM Privilege p WHERE p.name = :name")
    Privilege findByName(@Param("name") String name);

    /**
     * Find privileges by names (batch operation).
     * Uses parameterized query with IN clause for safe batch operations.
     * 
     * @param names list of privilege names to search for
     * @return list of matching privileges
     */
    @Query("SELECT p FROM Privilege p WHERE p.name IN :names")
    List<Privilege> findByNames(@Param("names") List<String> names);

    /**
     * Check if privilege exists by name.
     * 
     * @param name the privilege name to check
     * @return true if privilege exists, false otherwise
     */
    @Query("SELECT COUNT(p) > 0 FROM Privilege p WHERE p.name = :name")
    boolean existsByName(@Param("name") String name);

    /**
     * Find all privileges for a specific role.
     * Uses JOIN to fetch privileges associated with a role.
     * 
     * @param roleId the role ID
     * @return list of privileges for the role
     */
    @Query("SELECT DISTINCT p FROM Privilege p JOIN p.roles r WHERE r.id = :roleId")
    List<Privilege> findByRoleId(@Param("roleId") Long roleId);

    /**
     * Find all privileges for a specific role by role name.
     * 
     * @param roleName the role name
     * @return list of privileges for the role
     */
    @Query("SELECT DISTINCT p FROM Privilege p JOIN p.roles r WHERE r.name = :roleName")
    List<Privilege> findByRoleName(@Param("roleName") String roleName);

    /**
     * Find all privileges for a specific user.
     * Uses multiple JOINs to get user privileges through roles.
     * 
     * @param userId the user ID
     * @return list of privileges for the user
     */
    @Query("SELECT DISTINCT p FROM Privilege p " +
           "JOIN p.roles r " +
           "JOIN r.users u " +
           "WHERE u.id = :userId")
    List<Privilege> findByUserId(@Param("userId") Long userId);

    /**
     * Find all privileges for a specific user by username.
     * 
     * @param username the username
     * @return list of privileges for the user
     */
    @Query("SELECT DISTINCT p FROM Privilege p " +
           "JOIN p.roles r " +
           "JOIN r.users u " +
           "WHERE u.username = :username")
    List<Privilege> findByUsername(@Param("username") String username);

    /**
     * Check if a user has a specific privilege.
     * 
     * @param userId the user ID
     * @param privilegeName the privilege name
     * @return true if user has the privilege, false otherwise
     */
    @Query("SELECT COUNT(p) > 0 FROM Privilege p " +
           "JOIN p.roles r " +
           "JOIN r.users u " +
           "WHERE u.id = :userId AND p.name = :privilegeName")
    boolean userHasPrivilege(@Param("userId") Long userId, @Param("privilegeName") String privilegeName);

    /**
     * Check if a role has a specific privilege.
     * 
     * @param roleId the role ID
     * @param privilegeName the privilege name
     * @return true if role has the privilege, false otherwise
     */
    @Query("SELECT COUNT(p) > 0 FROM Privilege p " +
           "JOIN p.roles r " +
           "WHERE r.id = :roleId AND p.name = :privilegeName")
    boolean roleHasPrivilege(@Param("roleId") Long roleId, @Param("privilegeName") String privilegeName);

    /**
     * Find privileges that are not assigned to any role.
     * Useful for cleanup operations.
     * 
     * @return list of orphaned privileges
     */
    @Query("SELECT p FROM Privilege p WHERE p.roles IS EMPTY")
    List<Privilege> findOrphanedPrivileges();

    /**
     * Count roles that have a specific privilege.
     * 
     * @param privilegeName the privilege name
     * @return number of roles with the privilege
     */
    @Query("SELECT COUNT(DISTINCT r) FROM Privilege p " +
           "JOIN p.roles r " +
           "WHERE p.name = :privilegeName")
    long countRolesWithPrivilege(@Param("privilegeName") String privilegeName);

    /**
     * Find privileges with names containing a search term.
     * Case-insensitive search for admin interfaces.
     * 
     * @param searchTerm the search term
     * @return list of matching privileges
     */
    @Query("SELECT p FROM Privilege p WHERE LOWER(p.name) LIKE LOWER(CONCAT('%', :searchTerm, '%')) " +
           "OR LOWER(p.description) LIKE LOWER(CONCAT('%', :searchTerm, '%'))")
    List<Privilege> findByNameOrDescriptionContaining(@Param("searchTerm") String searchTerm);

    /**
     * Find all privileges ordered by name.
     * 
     * @return list of all privileges sorted by name
     */
    @Query("SELECT p FROM Privilege p ORDER BY p.name ASC")
    List<Privilege> findAllOrderByName();

    /**
     * Find privileges by description containing search term.
     * 
     * @param description the description search term
     * @return list of matching privileges
     */
    @Query("SELECT p FROM Privilege p WHERE LOWER(p.description) LIKE LOWER(CONCAT('%', :description, '%'))")
    List<Privilege> findByDescriptionContaining(@Param("description") String description);
}