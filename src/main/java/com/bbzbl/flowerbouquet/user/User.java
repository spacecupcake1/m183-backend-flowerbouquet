package com.bbzbl.flowerbouquet.user;

import java.util.Collection;

import com.bbzbl.flowerbouquet.security.Role;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.Table;
import lombok.Data;

/**
 * Entity class representing a User in the system.
 */
@Data
@Entity
@Table(name = "users")
public class User {

    // Primary key for the User entity
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Username of the user, must be unique and not null
    @Column(nullable = false, unique = true)
    private String username;

    // First name of the user, must not be null
    @Column(nullable = false)
    private String firstname;

    // Last name of the user, must not be null
    @Column(nullable = false)
    private String lastname;

    // Email of the user, must be unique and not null
    @Column(nullable = false, unique = true)
    private String email;

    // Password of the user, must not be null
    @Column(nullable = false)
    private String password;

    // User roles relationship
    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
            name = "users_roles",
            joinColumns = @JoinColumn(name = "user_id", referencedColumnName = "id"),
            inverseJoinColumns = @JoinColumn(name = "role_id", referencedColumnName = "id")
    )
    private Collection<Role> roles;
}