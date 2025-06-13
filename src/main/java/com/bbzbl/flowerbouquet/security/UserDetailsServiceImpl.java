package com.bbzbl.flowerbouquet.security;

import java.util.Collection;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.bbzbl.flowerbouquet.user.User;
import com.bbzbl.flowerbouquet.user.UserRepository;

/**
 * Implementation of Spring Security's UserDetailsService.
 * This service is responsible for loading user-specific data during authentication.
 */
@Service("userDetailsService")
@Transactional
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    /**
     * Loads the user details by username for Spring Security authentication.
     * 
     * @param username the username of the user to load
     * @return UserDetails containing user information and authorities
     * @throws UsernameNotFoundException if user is not found
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        try {
            User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));

            return new CustomUserPrincipal(
                user.getId(),
                user.getUsername(),
                user.getPassword(),
                user.getFirstname(),
                user.getLastname(),
                user.getEmail(),
                mapRolesToAuthorities(user.getRoles()),
                user.getRoles()
            );

        } catch (Exception e) {
            throw new UsernameNotFoundException("Error loading user: " + username, e);
        }
    }

    /**
     * Maps user roles to Spring Security authorities.
     * 
     * @param roles the user's roles
     * @return collection of GrantedAuthority
     */
    private Collection<? extends GrantedAuthority> mapRolesToAuthorities(Collection<Role> roles) {
        return roles.stream()
            .flatMap(role -> {
                // Add role authority
                var authorities = java.util.stream.Stream.of(new SimpleGrantedAuthority(role.getName()));
                
                // Add privilege authorities if they exist
                if (role.getPrivileges() != null && !role.getPrivileges().isEmpty()) {
                    var privilegeAuthorities = role.getPrivileges().stream()
                        .map(privilege -> new SimpleGrantedAuthority(privilege.getName()));
                    authorities = java.util.stream.Stream.concat(authorities, privilegeAuthorities);
                }
                
                return authorities;
            })
            .collect(Collectors.toList());
    }

    /**
     * Custom UserDetails implementation that holds additional user information.
     */
    public static class CustomUserPrincipal implements UserDetails {
        
        private final Long id;
        private final String username;
        private final String password;
        private final String firstname;
        private final String lastname;
        private final String email;
        private final Collection<? extends GrantedAuthority> authorities;
        private final Collection<Role> roles;

        public CustomUserPrincipal(Long id, String username, String password, String firstname, 
                                 String lastname, String email, 
                                 Collection<? extends GrantedAuthority> authorities,
                                 Collection<Role> roles) {
            this.id = id;
            this.username = username;
            this.password = password;
            this.firstname = firstname;
            this.lastname = lastname;
            this.email = email;
            this.authorities = authorities;
            this.roles = roles;
        }

        // UserDetails interface methods
        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            return authorities;
        }

        @Override
        public String getPassword() {
            return password;
        }

        @Override
        public String getUsername() {
            return username;
        }

        @Override
        public boolean isAccountNonExpired() {
            return true; // In production, implement based on business requirements
        }

        @Override
        public boolean isAccountNonLocked() {
            return true; // In production, implement account locking mechanism
        }

        @Override
        public boolean isCredentialsNonExpired() {
            return true; // In production, implement password expiration
        }

        @Override
        public boolean isEnabled() {
            return true; // In production, implement user enabling/disabling
        }

        // Additional getters for user information
        public Long getId() {
            return id;
        }

        public String getFirstname() {
            return firstname;
        }

        public String getLastname() {
            return lastname;
        }

        public String getEmail() {
            return email;
        }

        public Collection<Role> getRoles() {
            return roles;
        }

        /**
         * Check if user has a specific role.
         */
        public boolean hasRole(String roleName) {
            return authorities.stream()
                .anyMatch(authority -> authority.getAuthority().equals(roleName));
        }

        /**
         * Check if user has admin role.
         */
        public boolean isAdmin() {
            return hasRole("ROLE_ADMIN");
        }

        /**
         * Check if user has a specific privilege.
         */
        public boolean hasPrivilege(String privilegeName) {
            return authorities.stream()
                .anyMatch(authority -> authority.getAuthority().equals(privilegeName));
        }

        @Override
        public String toString() {
            return "CustomUserPrincipal{" +
                    "id=" + id +
                    ", username='" + username + '\'' +
                    ", firstname='" + firstname + '\'' +
                    ", lastname='" + lastname + '\'' +
                    ", email='" + email + '\'' +
                    ", authorities=" + authorities +
                    '}';
        }
    }
}