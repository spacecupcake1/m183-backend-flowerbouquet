package com.bbzbl.flowerbouquet.security;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
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
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.security.web.header.writers.XContentTypeOptionsHeaderWriter;
import org.springframework.security.web.header.writers.XXssProtectionHeaderWriter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

/**
 * Complete Security configuration with REST API authentication (no form login)
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private SecurityHeadersConfig.ContentSecurityPolicyHeaderWriter cspHeaderWriter;

    @Autowired
    private SecurityFilter securityFilter;

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
        authProvider.setPasswordEncoder(passwordEncoder);
        return authProvider;
    }

    /**
     * Complete security filter chain with REST API authentication.
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // Disable CSRF for REST API (using session-based auth with same-origin policy)
            .csrf(csrf -> csrf.disable())
            
            // CORS configuration
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            
            // Add custom security filter before authentication
            .addFilterBefore(securityFilter, UsernamePasswordAuthenticationFilter.class)
            
            // Request authorization configuration
            .authorizeHttpRequests(authz -> authz
                // Public endpoints
                .requestMatchers("/", "/index.html", "/favicon.ico").permitAll()
                .requestMatchers("/images/**", "/css/**", "/js/**", "/assets/**").permitAll()
                
                // Authentication endpoints - public
                .requestMatchers(HttpMethod.POST, "/api/users/login", "/api/users/register").permitAll()
                .requestMatchers(HttpMethod.POST, "/api/users/logout").authenticated()
                .requestMatchers(HttpMethod.GET, "/api/users/current").authenticated()
                
                // Flower endpoints - require authentication
                .requestMatchers(HttpMethod.GET, "/api/flowers", "/api/flowers/**").hasAnyRole("USER", "ADMIN")
                .requestMatchers(HttpMethod.GET, "/api/flowers/search").hasAnyRole("USER", "ADMIN")
                .requestMatchers(HttpMethod.GET, "/api/flowers/availability/**").hasAnyRole("USER", "ADMIN")
                
                // Admin-only endpoints for flower management
                .requestMatchers(HttpMethod.POST, "/api/flowers").hasRole("ADMIN")
                .requestMatchers(HttpMethod.PUT, "/api/flowers/**").hasRole("ADMIN")
                .requestMatchers(HttpMethod.DELETE, "/api/flowers/**").hasRole("ADMIN")
                
                // Admin endpoints
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .requestMatchers("/api/users/admin/**").hasRole("ADMIN")
                
                // User management endpoints
                .requestMatchers(HttpMethod.GET, "/api/users").hasRole("ADMIN")
                .requestMatchers(HttpMethod.GET, "/api/users/**").hasAnyRole("USER", "ADMIN")
                .requestMatchers(HttpMethod.PUT, "/api/users/**").hasAnyRole("USER", "ADMIN")
                .requestMatchers(HttpMethod.DELETE, "/api/users/**").hasRole("ADMIN")
                
                // Development endpoints (H2 console) - REMOVE IN PRODUCTION
                .requestMatchers("/h2-console/**").permitAll()
                
                // Management endpoints
                .requestMatchers("/management/health").permitAll()
                
                // All other requests require authentication
                .anyRequest().authenticated()
            )
            
            // Enhanced security headers
            .headers(headers -> headers
                .frameOptions().sameOrigin() // Allow same origin for H2 console in dev
                .contentTypeOptions().and()
                .httpStrictTransportSecurity(hstsConfig -> hstsConfig
                    .maxAgeInSeconds(31536000)
                    .includeSubDomains(true)
                    .preload(true)
                )
                .addHeaderWriter(cspHeaderWriter)
                .addHeaderWriter(new ReferrerPolicyHeaderWriter(
                    ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN))
                .addHeaderWriter(new XContentTypeOptionsHeaderWriter())
                .addHeaderWriter(new XXssProtectionHeaderWriter())
            )
            
            // Session management configuration
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                .sessionFixation().migrateSession()
                .maximumSessions(3)
                .maxSessionsPreventsLogin(false)
                .and()
                .invalidSessionUrl("/login?expired=true")
            )
            
            // Authentication provider
            .authenticationProvider(authenticationProvider())
            
            // Exception handling for REST API
            .exceptionHandling(exceptions -> exceptions
                .authenticationEntryPoint((request, response, authException) -> {
                    response.setStatus(401);
                    response.setContentType("application/json");
                    response.setCharacterEncoding("UTF-8");
                    response.getWriter().write("{\"error\":\"Authentication required\",\"message\":\"Please log in to access this resource\"}");
                })
                .accessDeniedHandler((request, response, accessDeniedException) -> {
                    response.setStatus(403);
                    response.setContentType("application/json");
                    response.setCharacterEncoding("UTF-8");
                    response.getWriter().write("{\"error\":\"Access denied\",\"message\":\"You don't have permission to access this resource\"}");
                })
            );

        return http.build();
    }

    /**
     * CORS configuration for frontend-backend communication.
     * ENHANCED: More comprehensive CORS setup to fix preflight issues
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        
        // Allow specific origins (update for production)
        configuration.setAllowedOriginPatterns(Arrays.asList(
            "http://localhost:4200",
            "https://localhost:4200",
            "http://127.0.0.1:4200",
            "http://localhost:3000",
            "https://yourdomain.com" // Add your production domain
        ));
        
        // Allow ALL HTTP methods (including OPTIONS for preflight)
        configuration.setAllowedMethods(Arrays.asList("*"));
        
        // Allow ALL headers
        configuration.setAllowedHeaders(Arrays.asList("*"));
        
        // Expose headers that frontend can read
        configuration.setExposedHeaders(Arrays.asList(
            "Access-Control-Allow-Origin",
            "Access-Control-Allow-Credentials",
            "X-Content-Type-Options",
            "Authorization"
        ));
        
        // CRITICAL: Allow credentials for session-based auth
        configuration.setAllowCredentials(true);
        
        // Cache preflight response for 1 hour
        configuration.setMaxAge(3600L);
        
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        
        // Apply to ALL endpoints
        source.registerCorsConfiguration("/**", configuration);
        
        return source;
    }
}