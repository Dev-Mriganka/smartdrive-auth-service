package com.smartdrive.authservice.config;

import java.time.Duration;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfigurationSource;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Industry Standard OAuth2 Authorization Server Configuration
 * 
 * This implements the OAuth2/OIDC Authorization Server according to your architecture:
 * - Handles /oauth2/authorize endpoint for authentication
 * - Provides /oauth2/token endpoint for token issuance
 * - Exposes /oauth2/jwks endpoint for public key distribution
 * - Uses RSA keys for JWT signing (Auth Service private, Gateway public)
 * - Supports standard OAuth2 flows: Authorization Code, Refresh Token, Client Credentials
 */
@Configuration
@RequiredArgsConstructor
@Profile("!docker") // Disable temporarily for debugging
@Slf4j
public class OAuth2Config {

    /**
     * OAuth2 Authorization Server Security Filter Chain
     * Handles all OAuth2/OIDC protocol endpoints
     */
    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                new OAuth2AuthorizationServerConfigurer();
        
        // TEMPORARILY DISABLED FOR DEBUGGING
        http.securityMatcher("/oauth2/**", "/.well-known/**", "/connect/**")
            .authorizeHttpRequests((authorize) -> authorize
                .anyRequest().permitAll()
            );
            
        log.info("🛡️ OAuth2 Authorization Server security filter chain configured (SIMPLIFIED FOR DEBUG)");
        log.info("📍 OAuth2 endpoints temporarily disabled");
        
        return http.build();
    }

    /**
     * Default Security Filter Chain for API endpoints
     * Protects regular API endpoints with JWT validation
     */
    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http,
            CorsConfigurationSource corsConfigurationSource) throws Exception {
        http
            .authorizeHttpRequests((authorize) -> authorize
                // TEMPORARY: Allow all requests for debugging
                .anyRequest().permitAll()
            )
            // CORS configuration
            .cors(cors -> cors.configurationSource(corsConfigurationSource))
            // Disable CSRF for stateless API
            .csrf(AbstractHttpConfigurer::disable)
            // Disable all security temporarily
            .httpBasic(AbstractHttpConfigurer::disable)
            .formLogin(AbstractHttpConfigurer::disable)
            .logout(AbstractHttpConfigurer::disable)
            // Stateless session management
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            );
            
        log.info("🔐 SIMPLIFIED security filter chain - ALL REQUESTS PERMITTED FOR DEBUG");
        return http.build();
    }

    /**
     * Register OAuth2 clients that can use this Authorization Server
     * In production, this would be stored in database
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        // SmartDrive Web Client (for frontend applications)
        RegisteredClient webClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("smartdrive-web")
                .clientSecret("{noop}secret") // In production, use proper password encoding
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://localhost:3000/callback")
                .redirectUri("http://localhost:8080/callback")
                .redirectUri("http://localhost:5173/callback")
                .postLogoutRedirectUri("http://localhost:3000/")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope(OidcScopes.EMAIL)
                .scope("read")
                .scope("write")
                .clientSettings(ClientSettings.builder()
                    .requireAuthorizationConsent(false) // Skip consent for trusted clients
                    .build())
                .tokenSettings(TokenSettings.builder()
                    .accessTokenTimeToLive(Duration.ofMinutes(15)) // Short-lived access tokens
                    .refreshTokenTimeToLive(Duration.ofDays(7))    // Longer refresh tokens
                    .reuseRefreshTokens(false) // Token rotation for security
                    .build())
                .build();

        // API Gateway Internal Client (for service-to-service communication)
        RegisteredClient gatewayClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("api-gateway-internal")
                .clientSecret("{noop}gateway-secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("internal")
                .scope("validate")
                .tokenSettings(TokenSettings.builder()
                    .accessTokenTimeToLive(Duration.ofMinutes(30))
                    .build())
                .build();

        log.info("📋 Registered OAuth2 clients: smartdrive-web, api-gateway-internal");
        return new InMemoryRegisteredClientRepository(webClient, gatewayClient);
    }

    /**
     * OAuth2 Authorization Consent Service
     * Handles user consent for OAuth2 scopes
     */
    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService() {
        return new InMemoryOAuth2AuthorizationConsentService();
    }

    /**
     * OAuth2 Authorization Service
     * Stores authorization codes, access tokens, refresh tokens
     * In production, this should be backed by Redis or database
     */
    @Bean
    public OAuth2AuthorizationService authorizationService() {
        return new InMemoryOAuth2AuthorizationService();
    }

    /**
     * Password Encoder for client secrets and user passwords
     */
    // PasswordEncoder bean is defined in PasswordConfig to avoid duplicates

    /**
     * Authorization Server Settings
     * Configures the issuer URI and endpoint paths
     */
    @Bean
    public AuthorizationServerSettings authorizationServerSettings(
            @Value("${auth.service.issuer-uri:http://localhost:8082}") String issuerUri) {
        return AuthorizationServerSettings.builder()
                .issuer(issuerUri)
                .authorizationEndpoint("/oauth2/authorize")
                .tokenEndpoint("/oauth2/token")
                .jwkSetEndpoint("/oauth2/jwks")
                .tokenRevocationEndpoint("/oauth2/revoke")
                .tokenIntrospectionEndpoint("/oauth2/introspect")
                .oidcClientRegistrationEndpoint("/connect/register")
                .oidcUserInfoEndpoint("/userinfo")
                .oidcLogoutEndpoint("/connect/logout")
                .build();
    }

    /**
     * JWT Authentication Converter for Resource Server
     * Extracts authorities from JWT claims
     */
    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter authoritiesConverter = 
                new JwtGrantedAuthoritiesConverter();
        authoritiesConverter.setAuthorityPrefix("ROLE_");
        authoritiesConverter.setAuthoritiesClaimName("roles");

        JwtAuthenticationConverter jwtConverter = new JwtAuthenticationConverter();
        jwtConverter.setJwtGrantedAuthoritiesConverter(authoritiesConverter);
        
        log.info("🎯 JWT authentication converter configured with role extraction");
        return jwtConverter;
    }
}
