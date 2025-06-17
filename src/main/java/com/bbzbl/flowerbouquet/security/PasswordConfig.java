package com.bbzbl.flowerbouquet.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Separate configuration for PasswordEncoder to avoid circular dependencies.
 * This allows UserService to inject PasswordEncoder without creating a cycle with SecurityConfig.
 */
@Configuration
public class PasswordConfig {

    /**
     * Password encoder with BCrypt for secure password hashing.
     * BCrypt automatically handles salt generation and provides strong protection.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }
}