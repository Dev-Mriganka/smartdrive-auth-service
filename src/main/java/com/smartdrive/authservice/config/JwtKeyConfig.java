package com.smartdrive.authservice.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

/**
 * Industry Standard RSA JWT Key Configuration for OAuth2/OIDC
 * - Uses RSA-2048 asymmetric keys for stateless validation
 * - Auth Service keeps private key for signing
 * - API Gateway uses public key for validation via JWKS endpoint
 * - Supports proper OAuth2/OIDC token validation architecture
 */
@Configuration
@Slf4j
public class JwtKeyConfig {

    /**
     * Generate RSA Key Pair for JWT signing and validation
     * This is the core of the industry-standard OAuth2 architecture
     */
    @Bean
    public KeyPair rsaKeyPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048); // RSA-2048 for security
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            
            log.info("🔐 Generated RSA-2048 key pair for OAuth2 JWT signing");
            log.info("🔑 Private key algorithm: {}", keyPair.getPrivate().getAlgorithm());
            log.info("🔓 Public key algorithm: {}", keyPair.getPublic().getAlgorithm());
            
            return keyPair;
        } catch (Exception ex) {
            log.error("❌ Failed to generate RSA key pair", ex);
            throw new RuntimeException("Failed to generate RSA key pair for JWT", ex);
        }
    }
    
    /**
     * Create RSA JWK (JSON Web Key) for JWKS endpoint
     * This is what the API Gateway will fetch to validate tokens
     */
    @Bean
    public RSAKey rsaKey(KeyPair rsaKeyPair) {
        RSAPublicKey publicKey = (RSAPublicKey) rsaKeyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) rsaKeyPair.getPrivate();
        
        String keyId = "smartdrive-oauth2-" + UUID.randomUUID().toString();
        
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(keyId)
                .build();
                
        log.info("🆔 Generated RSA JWK with key ID: {}", keyId);
        return rsaKey;
    }
    
    /**
     * JWK Set for the JWKS endpoint (/oauth2/jwks)
     * This is the public endpoint that API Gateway calls to get public keys
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource(RSAKey rsaKey) {
        JWKSet jwkSet = new JWKSet(rsaKey);
        log.info("📋 Created JWK Set with {} keys for JWKS endpoint", jwkSet.size());
        return new ImmutableJWKSet<>(jwkSet);
    }
    
    /**
     * JWT Encoder for signing tokens with RSA private key
     * Used by Auth Service to create access tokens and ID tokens
     */
    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        log.info("🖊️ Created JWT encoder with RSA private key signing");
        return new NimbusJwtEncoder(jwkSource);
    }
    
    /**
     * JWT Decoder for validating tokens with RSA public key
     * Used by Auth Service for internal token validation
     */
    @Bean
    public JwtDecoder jwtDecoder(KeyPair rsaKeyPair) {
        RSAPublicKey publicKey = (RSAPublicKey) rsaKeyPair.getPublic();
        NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withPublicKey(publicKey).build();
        
        log.info("🔍 Created JWT decoder with RSA public key validation");
        return jwtDecoder;
    }
    
    /**
     * Get JWK Set for JWKS endpoint
     * Used by SimpleJwksController to expose the JWKS endpoint
     */
    public JWKSet getJwkSet() {
        try {
            RSAKey rsaKey = rsaKey(rsaKeyPair());
            return new JWKSet(rsaKey);
        } catch (Exception e) {
            log.error("❌ Error getting JWK Set: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to get JWK Set", e);
        }
    }
    
    /**
     * Get RSA Key for JWKS endpoint
     * Used by SimpleJwksController to expose the JWKS endpoint
     */
    public RSAKey getRsaKey() {
        try {
            return rsaKey(rsaKeyPair());
        } catch (Exception e) {
            log.error("❌ Error getting RSA Key: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to get RSA Key", e);
        }
    }
}
