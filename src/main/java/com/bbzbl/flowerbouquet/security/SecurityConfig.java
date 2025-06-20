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
 * Complete Security configuration with all enhanced security features
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
    private CustomAuthenticationSuccessHandler authenticationSuccessHandler;

    @Autowired
    private CustomAuthenticationFailureHandler authenticationFailureHandler;

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
     * Complete security filter chain with all security features.
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
            
            // Form login configuration
            .formLogin(form -> form
                .loginProcessingUrl("/api/users/login")
                .successHandler(authenticationSuccessHandler)
                .failureHandler(authenticationFailureHandler)
                .permitAll()
            )
            
            // Logout configuration
            .logout(logout -> logout
                .logoutUrl("/api/users/logout")
                .logoutSuccessHandler((request, response, authentication) -> {
                    response.setStatus(200);
                    response.setContentType("application/json");
                    response.setCharacterEncoding("UTF-8");
                    response.getWriter().write("{\"message\":\"Logout successful\"}");
                })
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID", "FLOWERSESSIONID")
                .clearAuthentication(true)
                .permitAll()
            )
            
            // Exception handling
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
        
        // Allow specific HTTP methods
        configuration.setAllowedMethods(Arrays.asList(
            "GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "HEAD"
        ));
        
        // Allow specific headers
        configuration.setAllowedHeaders(Arrays.asList(
            "Authorization", 
            "Content-Type", 
            "X-Requested-With", 
            "Accept", 
            "Origin",
            "Access-Control-Request-Method",
            "Access-Control-Request-Headers",
            "X-Content-Type-Options",
            "Cache-Control",
            "Pragma",
            "Expires",
            "X-Frame-Options",
            "X-XSS-Protection",
            "X-CSRF-TOKEN"
        ));
        
        // Expose headers that frontend can read
        configuration.setExposedHeaders(Arrays.asList(
            "Access-Control-Allow-Origin",
            "Access-Control-Allow-Credentials",
            "X-Content-Type-Options"
        ));
        
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);
        
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}