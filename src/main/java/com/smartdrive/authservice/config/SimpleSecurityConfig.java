package com.smartdrive.authservice.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfigurationSource;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Simplified Security Configuration for Custom Authentication
 *
 * Environment-based configuration:
 * - dev: Permissive for development and testing
 * - prod: Secure for production deployment
 */
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@Slf4j
public class SimpleSecurityConfig {

    private final CorsConfigurationSource corsConfigurationSource;

    /**
     * Development Security Configuration
     * Allows all requests for easier development and testing
     */
    @Bean
    @Profile("dev")
    public SecurityFilterChain devSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests((authorize) -> authorize
                .anyRequest().permitAll()
            )
            .csrf(AbstractHttpConfigurer::disable)
            .httpBasic(AbstractHttpConfigurer::disable)
            .formLogin(AbstractHttpConfigurer::disable)
            .logout(AbstractHttpConfigurer::disable)
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            .cors(cors -> cors.configurationSource(corsConfigurationSource));

        log.info("🔐 DEV security filter chain - ALL REQUESTS PERMITTED");
        return http.build();
    }

    /**
     * Production Security Configuration
     * Secure configuration with proper endpoint protection
     */
    @Bean
    @Profile("prod")
    public SecurityFilterChain prodSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests((authorize) -> authorize
                // Public endpoints
                .requestMatchers(
                    "/api/v1/auth/register",
                    "/api/v1/auth/login",
                    "/api/v1/auth/refresh",
                    "/api/v1/auth/verify-email",
                    "/api/v1/auth/forgot-password",
                    "/api/v1/auth/reset-password",
                    "/api/v1/auth/social/**",
                    "/api/v1/jwks",
                    "/actuator/health",
                    "/actuator/info"
                ).permitAll()
                // Internal service-to-service endpoints
                .requestMatchers("/api/internal/**").permitAll()
                // All other endpoints require authentication
                .anyRequest().authenticated()
            )
            .csrf(AbstractHttpConfigurer::disable)
            .httpBasic(AbstractHttpConfigurer::disable)
            .formLogin(AbstractHttpConfigurer::disable)
            .logout(AbstractHttpConfigurer::disable)
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            .cors(cors -> cors.configurationSource(corsConfigurationSource));

        log.info("🔐 PROD security filter chain - SECURED ENDPOINTS");
        return http.build();
    }
}
