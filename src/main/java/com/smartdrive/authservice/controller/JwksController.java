package com.smartdrive.authservice.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.smartdrive.authservice.config.JwtKeyConfig;

import java.security.interfaces.RSAPublicKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

/**
 * JWKS (JSON Web Key Set) Controller
 * 
 * This endpoint provides the public keys used to verify JWT tokens.
 * This enables the API Gateway to perform LOCAL JWT validation without
 * calling the auth service for each request (FAST validation!)
 * 
 * Part of the optimized authentication flow:
 * Frontend → API Gateway → Local JWT Validation (using JWKS) → Microservice
 */
@RestController
@RequestMapping("/.well-known")
@RequiredArgsConstructor
@Slf4j
public class JwksController {

    private final JwtEncoder jwtEncoder;
    private final KeyPair jwtKeyPair;
    private final String jwtKeyId;

    /**
     * JWKS endpoint for JWT public key distribution
     * 
     * This endpoint is called by:
     * 1. API Gateway during startup to get public keys
     * 2. API Gateway periodically to refresh keys
     * 
     * This enables FAST local JWT validation in API Gateway!
     */
    @GetMapping("/jwks.json")
    public ResponseEntity<Map<String, Object>> jwks() {
        log.debug("🔑 JWKS request - providing public keys for JWT validation");
        log.info("🔍 JWKS using key ID: {}", jwtKeyId);
        
        try {
            // Create RSA JWK from public key
            RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) jwtKeyPair.getPublic())
                    .keyID(jwtKeyId)
                    .algorithm(com.nimbusds.jose.Algorithm.parse("RS256"))
                    .keyUse(com.nimbusds.jose.jwk.KeyUse.SIGNATURE)
                    .build();
                    
            log.info("🔑 Created RSA key with ID: {}", rsaKey.getKeyID());
            
            // Create JWK Set
            JWKSet jwkSet = new JWKSet(rsaKey);
            
            // Return as JSON
            Map<String, Object> jwksJson = jwkSet.toJSONObject();
            
            log.debug("✅ JWKS provided successfully");
            return ResponseEntity.ok(jwksJson);
            
        } catch (Exception e) {
            log.error("❌ Error generating JWKS", e);
            return ResponseEntity.status(500).body(Map.of(
                "error", "server_error",
                "error_description", "Unable to generate JWKS"
            ));
        }
    }

    /**
     * OpenID Connect Discovery endpoint
     * Provides metadata about the auth server
     */
    @GetMapping("/openid_configuration")
    public ResponseEntity<Map<String, Object>> openidConfiguration() {
        log.debug("🔍 OpenID Connect discovery request");
        
        Map<String, Object> config = Map.of(
            "issuer", "http://auth-service:8085",
            "authorization_endpoint", "http://auth-service:8085/oauth2/authorize",
            "token_endpoint", "http://auth-service:8085/api/v1/auth/login",
            "userinfo_endpoint", "http://auth-service:8085/oauth2/userinfo", 
            "jwks_uri", "http://auth-service:8085/.well-known/jwks.json",
            "scopes_supported", new String[]{"openid", "profile", "email"},
            "response_types_supported", new String[]{"code", "token"},
            "grant_types_supported", new String[]{"authorization_code", "refresh_token"},
            "token_endpoint_auth_methods_supported", new String[]{"client_secret_post", "client_secret_basic"},
            "claims_supported", new String[]{"sub", "name", "email", "preferred_username", "given_name", "family_name"}
        );
        
        return ResponseEntity.ok(config);
    }

    /**
     * Generate RSA key pair for JWT signing
     * In production, load from secure key store
     */
    private static KeyPair generateKeyPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Unable to generate RSA key pair", e);
        }
    }
}
