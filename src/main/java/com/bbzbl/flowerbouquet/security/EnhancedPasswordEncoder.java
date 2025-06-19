package com.bbzbl.flowerbouquet.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class EnhancedPasswordEncoder {
    
    @Value("${app.security.pepper:MySecretPepperKey2024!@#$%^&*()}")
    private String pepper;
    
    private final PasswordEncoder bcryptEncoder;
    
    public EnhancedPasswordEncoder() {
        this.bcryptEncoder = new BCryptPasswordEncoder(12);
    }
    
    /**
     * Encode password with pepper + BCrypt (salt + hash)
     */
    public String encode(String rawPassword) {
        // Add pepper before hashing
        String pepperedPassword = rawPassword + pepper;
        
        // BCrypt handles salt generation automatically
        return bcryptEncoder.encode(pepperedPassword);
    }
    
    /**
     * Verify password with pepper + BCrypt
     */
    public boolean matches(String rawPassword, String encodedPassword) {
        // Add pepper before verification
        String pepperedPassword = rawPassword + pepper;
        
        return bcryptEncoder.matches(pepperedPassword, encodedPassword);
    }
}