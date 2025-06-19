// Update src/main/java/com/bbzbl/flowerbouquet/security/PasswordConfig.java

package com.bbzbl.flowerbouquet.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class PasswordConfig {

    @Autowired
    private EnhancedPasswordEncoder enhancedPasswordEncoder;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return enhancedPasswordEncoder;
    }
}