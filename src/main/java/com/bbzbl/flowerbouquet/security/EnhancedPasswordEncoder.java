// Update src/main/java/com/bbzbl/flowerbouquet/security/EnhancedPasswordEncoder.java

package com.bbzbl.flowerbouquet.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class EnhancedPasswordEncoder implements PasswordEncoder {
    
    @Value("${app.security.pepper:MySecretPepperKey2024!@#$%^&*()}")
    private String pepper;
    
    private final PasswordEncoder bcryptEncoder;
    
    public EnhancedPasswordEncoder() {
        this.bcryptEncoder = new BCryptPasswordEncoder(12);
    }
    
    @Override
    public String encode(CharSequence rawPassword) {
        // Add pepper before hashing
        String pepperedPassword = rawPassword.toString() + pepper;
        
        // BCrypt handles salt generation automatically
        return bcryptEncoder.encode(pepperedPassword);
    }
    
    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        // Add pepper before verification
        String pepperedPassword = rawPassword.toString() + pepper;
        
        return bcryptEncoder.matches(pepperedPassword, encodedPassword);
    }
}