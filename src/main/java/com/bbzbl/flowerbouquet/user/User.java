package com.bbzbl.flowerbouquet.user;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.bbzbl.flowerbouquet.security.Role;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * User entity implementing Spring Security UserDetails for authentication.
 * Contains comprehensive security features including account locking, 
 * email verification, and role-based authorization.
 */
@Entity
@Table(name = "users", 
       uniqueConstraints = {
           @UniqueConstraint(columnNames = "username"),
           @UniqueConstraint(columnNames = "email")
       })
public class User implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank
    @Size(min = 3, max = 50)
    @Column(nullable = false, unique = true)
    private String username;

    @NotBlank
    @Email
    @Size(max = 100)
    @Column(nullable = false, unique = true)
    private String email;

    @NotBlank
    @Size(min = 60, max = 60) // BCrypt always produces 60-character hashes
    @Column(nullable = false)
    @JsonIgnore // Never serialize password
    private String password;

    @NotBlank
    @Size(min = 2, max = 50)
    @Column(name = "firstname")
    private String firstname;

    @NotBlank
    @Size(min = 2, max = 50)
    @Column(name = "lastname")
    private String lastname;

    @Column(name = "email_verified")
    private Boolean emailVerified = false;

    @Column(name = "account_non_expired")
    @JsonIgnore // Don't expose internal security flags
    private Boolean accountNonExpired = true;

    @Column(name = "account_non_locked")
    @JsonIgnore // Don't expose internal security flags
    private Boolean accountNonLocked = true;

    @Column(name = "credentials_non_expired")
    @JsonIgnore // Don't expose internal security flags
    private Boolean credentialsNonExpired = true;

    @Column(name = "enabled")
    @JsonIgnore // Don't expose internal security flags
    private Boolean enabled = true;

    @Column(name = "failed_login_attempts")
    @JsonIgnore // Don't expose security details
    private Integer failedLoginAttempts = 0;

    @Column(name = "last_failed_login")
    @JsonIgnore // Don't expose security details
    private LocalDateTime lastFailedLogin;

    @Column(name = "account_locked_until")
    @JsonIgnore // Don't expose security details
    private LocalDateTime accountLockedUntil;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @Column(name = "last_login")
    private LocalDateTime lastLogin;

    /**
     * User roles for authorization - Many-to-Many relationship with Role entity
     * FIXED: Break circular reference with @JsonIgnore on the Set<Role> and provide role names via getter
     */
    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
        name = "user_roles",
        joinColumns = @JoinColumn(name = "user_id"),
        inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    @JsonIgnore // Ignore the full Role objects to prevent circular reference
    private Set<Role> roles = new HashSet<>();

    // Constructors
    public User() {}

    public User(String username, String email, String password, String firstname, String lastname) {
        this.username = username;
        this.email = email;
        this.password = password;
        this.firstname = firstname;
        this.lastname = lastname;
    }

    // ========== JSON SERIALIZATION HELPERS ==========

    /**
     * Get role names for JSON serialization (instead of full Role objects)
     */
    @JsonProperty("roles")
    public Set<String> getRoleNames() {
        return roles.stream()
                .map(Role::getName)
                .collect(Collectors.toSet());
    }

    /**
     * Check if user is admin for JSON serialization
     */
    @JsonProperty("isAdmin")
    public boolean isAdmin() {
        return roles.stream()
                .anyMatch(role -> "ROLE_ADMIN".equals(role.getName()));
    }

    // ========== UserDetails implementation ==========
    
    @Override
    @JsonIgnore
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return roles.stream()
                .map(role -> new SimpleGrantedAuthority(role.getName()))
                .collect(Collectors.toSet());
    }

    @Override
    @JsonIgnore
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    @JsonIgnore
    public boolean isAccountNonExpired() {
        return accountNonExpired != null ? accountNonExpired : true;
    }

    @Override
    @JsonIgnore
    public boolean isAccountNonLocked() {
        if (accountLockedUntil != null && accountLockedUntil.isAfter(LocalDateTime.now())) {
            return false;
        }
        return accountNonLocked != null ? accountNonLocked : true;
    }

    @Override
    @JsonIgnore
    public boolean isCredentialsNonExpired() {
        return credentialsNonExpired != null ? credentialsNonExpired : true;
    }

    @Override
    @JsonIgnore
    public boolean isEnabled() {
        return enabled != null ? enabled : true;
    }

    // ========== GETTERS AND SETTERS ==========

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public void setUsername(String username) { this.username = username; }

    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }

    public void setPassword(String password) { this.password = password; }

    public String getFirstname() { return firstname; }
    public void setFirstname(String firstname) { this.firstname = firstname; }

    public String getLastname() { return lastname; }
    public void setLastname(String lastname) { this.lastname = lastname; }

    public Boolean getEmailVerified() { return emailVerified; }
    public void setEmailVerified(Boolean emailVerified) { this.emailVerified = emailVerified; }

    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }

    public LocalDateTime getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(LocalDateTime updatedAt) { this.updatedAt = updatedAt; }

    public LocalDateTime getLastLogin() { return lastLogin; }
    public void setLastLogin(LocalDateTime lastLogin) { this.lastLogin = lastLogin; }

    // Internal getters/setters for Role management (not exposed via JSON)
    public Set<Role> getRoles() { return roles; }
    public void setRoles(Set<Role> roles) { this.roles = roles; }

    public Boolean getAccountNonExpired() { return accountNonExpired; }
    public void setAccountNonExpired(Boolean accountNonExpired) { this.accountNonExpired = accountNonExpired; }

    public Boolean getAccountNonLocked() { return accountNonLocked; }
    public void setAccountNonLocked(Boolean accountNonLocked) { this.accountNonLocked = accountNonLocked; }

    public Boolean getCredentialsNonExpired() { return credentialsNonExpired; }
    public void setCredentialsNonExpired(Boolean credentialsNonExpired) { this.credentialsNonExpired = credentialsNonExpired; }

    public Boolean getEnabled() { return enabled; }
    public void setEnabled(Boolean enabled) { this.enabled = enabled; }

    public Integer getFailedLoginAttempts() { return failedLoginAttempts; }
    public void setFailedLoginAttempts(Integer failedLoginAttempts) { this.failedLoginAttempts = failedLoginAttempts; }

    public LocalDateTime getLastFailedLogin() { return lastFailedLogin; }
    public void setLastFailedLogin(LocalDateTime lastFailedLogin) { this.lastFailedLogin = lastFailedLogin; }

    public LocalDateTime getAccountLockedUntil() { return accountLockedUntil; }
    public void setAccountLockedUntil(LocalDateTime accountLockedUntil) { this.accountLockedUntil = accountLockedUntil; }

    // ========== JPA LIFECYCLE METHODS ==========

    @PrePersist
    protected void onCreate() {
        this.createdAt = LocalDateTime.now();
        this.updatedAt = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        this.updatedAt = LocalDateTime.now();
    }

    // ========== UTILITY METHODS ==========

    @Override
    public String toString() {
        return "User{" +
                "id=" + id +
                ", username='" + username + '\'' +
                ", email='" + email + '\'' +
                ", firstname='" + firstname + '\'' +
                ", lastname='" + lastname + '\'' +
                '}';
    }
}