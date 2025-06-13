package com.bbzbl.flowerbouquet.security;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

/**
 * Corrected Security configuration with proper dependency injection.
 * PasswordEncoder is injected from PasswordConfig to avoid circular dependencies.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private PasswordEncoder passwordEncoder; // Injected from PasswordConfig

    // These are automatically found because they're @Component annotated
    @Autowired
    private CustomAuthenticationSuccessHandler authenticationSuccessHandler;

    @Autowired
    private CustomAuthenticationFailureHandler authenticationFailureHandler;

    /**
     * Authentication manager for handling authentication requests.
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    /**
     * DaoAuthenticationProvider for database-based authentication.
     */
    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder); // Use autowired PasswordEncoder
        return authProvider;
    }

    /**
     * HTTP session event publisher for session management events.
     */
    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }

    /**
     * Main security filter chain configuration.
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // CORS configuration
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            
            // CSRF protection (disabled for API)
            .csrf(csrf -> csrf.disable())
            
            // Basic security headers
            .headers(headers -> headers
                .frameOptions().deny()
                .contentTypeOptions().and()
            )
            
            // Authorization rules
            .authorizeHttpRequests(authz -> authz
                // Public endpoints
                .requestMatchers("/api/users/register", "/api/users/login").permitAll()
                .requestMatchers("/error", "/favicon.ico").permitAll()
                
                // Admin endpoints
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .requestMatchers("/api/users/admin/**").hasRole("ADMIN")
                
                // Moderator or Admin endpoints
                .requestMatchers("/api/moderator/**").hasAnyRole("MODERATOR", "ADMIN")
                
                // Authenticated user endpoints
                .requestMatchers("/api/users/current", "/api/users/logout").authenticated()
                .requestMatchers("/api/users/profile/**").authenticated()
                
                // Default: permit all other requests
                .anyRequest().permitAll()
            )
            
            // Session management
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                .sessionFixation().migrateSession()
                .maximumSessions(3)
                .maxSessionsPreventsLogin(false)
            )
            
            // Authentication configuration
            .authenticationProvider(authenticationProvider())
            
            // REMOVED: Form login configuration - we handle login through REST API
            // .formLogin(form -> form
            //     .loginProcessingUrl("/api/users/login")
            //     .successHandler(authenticationSuccessHandler)
            //     .failureHandler(authenticationFailureHandler)
            //     .permitAll()
            // )
            
            // Logout configuration
            .logout(logout -> logout
                .logoutUrl("/api/users/logout")
                .logoutSuccessHandler((request, response, authentication) -> {
                    response.setStatus(200);
                    response.setContentType("application/json");
                    response.getWriter().write("{\"message\":\"Logout successful\"}");
                })
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID")
                .permitAll()
            )
            
            // Exception handling
            .exceptionHandling(exceptions -> exceptions
                .authenticationEntryPoint((request, response, authException) -> {
                    response.setStatus(401);
                    response.setContentType("application/json");
                    response.getWriter().write("{\"error\":\"Authentication required\"}");
                })
                .accessDeniedHandler((request, response, accessDeniedException) -> {
                    response.setStatus(403);
                    response.setContentType("application/json");
                    response.getWriter().write("{\"error\":\"Access denied\"}");
                })
            );

        return http.build();
    }

    /**
     * CORS configuration for frontend-backend communication.
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        
        configuration.setAllowedOriginPatterns(Arrays.asList(
            "http://localhost:4200",
            "https://localhost:4200",
            "http://127.0.0.1:4200"
        ));
        
        configuration.setAllowedMethods(Arrays.asList(
            "GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"
        ));
        
        // Expanded allowed headers to include common headers and the problematic one
        configuration.setAllowedHeaders(Arrays.asList(
            "Authorization", 
            "Content-Type", 
            "X-Requested-With", 
            "Accept", 
            "Origin",
            "Access-Control-Request-Method",
            "Access-Control-Request-Headers",
            "X-Content-Type-Options",  // Add the problematic header
            "Cache-Control",
            "Pragma",
            "Expires",
            "X-Frame-Options",
            "X-XSS-Protection"
        ));
        
        // You can also use "*" for all headers (less secure but more permissive)
        // configuration.setAllowedHeaders(Arrays.asList("*"));
        
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);
        
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    // NOTE: No @Bean methods for CustomAuthenticationSuccessHandler and CustomAuthenticationFailureHandler
    // because they are already @Component annotated and autowired above
}