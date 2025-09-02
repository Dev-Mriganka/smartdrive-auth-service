package com.smartdrive.authservice.controller;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 * JWKS (JSON Web Key Set) Controller
 * 
 * This is the crucial endpoint that enables the industry-standard OAuth2 architecture:
 * - Auth Service exposes public keys via /oauth2/jwks
 * - API Gateway fetches these keys to validate JWT tokens
 * - Enables stateless, decoupled JWT validation across services
 * 
 * This follows RFC 7517 (JSON Web Key) and RFC 7518 (JSON Web Algorithms)
 */
@RestController
@RequestMapping("/oauth2")
@RequiredArgsConstructor
@Slf4j
public class JwksController {

    private final JWKSource<SecurityContext> jwkSource;

    /**
     * JWKS Endpoint - RFC 7517
     * 
     * This endpoint is called by:
     * 1. API Gateway to fetch public keys for JWT validation
     * 2. Client applications for token verification
     * 3. Other microservices that need to validate our JWTs
     * 
     * The response contains RSA public keys that can verify JWT signatures
     * created by this Auth Service's private keys.
     */
    @GetMapping("/jwks")
    public ResponseEntity<Map<String, Object>> jwks() {
        try {
            // Get the current JWK Set with all available keys
            JWKSet jwkSet = new JWKSet(jwkSource.get(null, null));
            
            log.debug("🔑 JWKS endpoint called - returning {} keys", jwkSet.size());
            log.debug("📊 Key IDs in set: {}", 
                jwkSet.getKeys().stream()
                    .map(key -> key.getKeyID())
                    .toList());
            
            // Convert to standard JWKS format
            Map<String, Object> jwksResponse = jwkSet.toJSONObject();
            
            return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_JSON)
                .header("Cache-Control", "public, max-age=3600") // Cache for 1 hour
                .header("Access-Control-Allow-Origin", "*") // Allow cross-origin for public keys
                .body(jwksResponse);
                
        } catch (Exception e) {
            log.error("❌ Failed to generate JWKS response", e);
            return ResponseEntity.internalServerError().build();
        }
    }

    /**
     * OpenID Connect Discovery Endpoint
     * Provides metadata about this Authorization Server
     */
    @GetMapping("/.well-known/openid-configuration")
    public ResponseEntity<Map<String, Object>> openidConfiguration() {
        Map<String, Object> config = new HashMap<>();
        config.put("issuer", "http://localhost:8082");
        config.put("authorization_endpoint", "http://localhost:8082/oauth2/authorize");
        config.put("token_endpoint", "http://localhost:8082/oauth2/token");
        config.put("jwks_uri", "http://localhost:8082/oauth2/jwks");
        config.put("userinfo_endpoint", "http://localhost:8082/userinfo");
        config.put("end_session_endpoint", "http://localhost:8082/connect/logout");
        config.put("response_types_supported", new String[]{"code", "token", "id_token"});
        config.put("subject_types_supported", new String[]{"public"});
        config.put("id_token_signing_alg_values_supported", new String[]{"RS256"});
        config.put("scopes_supported", new String[]{"openid", "profile", "email", "read", "write"});
        config.put("claims_supported", new String[]{"sub", "aud", "iss", "exp", "iat", "email", "name", "roles"});
        
        log.debug("📋 OpenID Connect configuration requested");
        
        return ResponseEntity.ok()
            .contentType(MediaType.APPLICATION_JSON)
            .header("Cache-Control", "public, max-age=86400") // Cache for 24 hours
            .body(config);
    }
}
