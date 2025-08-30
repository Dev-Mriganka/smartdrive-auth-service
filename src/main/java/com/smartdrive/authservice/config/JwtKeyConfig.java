package com.smartdrive.authservice.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.UUID;

/**
 * Secure JWT key configuration following industry standards
 * - Uses strong RSA keys (2048-bit minimum)
 * - Generates cryptographically secure key IDs
 * - Ensures consistent key usage across all components
 * - Supports key rotation in production environments
 */
@Configuration
@Slf4j
public class JwtKeyConfig {

    /**
     * Generate a secure, unique key ID for JWT keys
     * Uses UUID for uniqueness and security
     */
    @Bean
    public String jwtKeyId(@Value("${app.jwt.key-id:#{null}}") String configuredKeyId) {
        // Allow configuration override for production key rotation
        if (configuredKeyId != null && !configuredKeyId.trim().isEmpty()) {
            log.info("🔑 Using configured JWT key ID: {}", configuredKeyId);
            return configuredKeyId;
        }
        
        // Generate secure UUID-based key ID
        String keyId = "smartdrive-" + UUID.randomUUID().toString();
        log.info("🔑 Generated secure JWT key ID: {}", keyId);
        log.info("📊 JWT Key Config bean created successfully with ID: {}", keyId);
        return keyId;
    }

    /**
     * Generate cryptographically strong RSA key pair
     * Uses 2048-bit keys with secure random generation
     */
    @Bean
    public KeyPair jwtKeyPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            
            // Use SecureRandom for cryptographically strong key generation
            SecureRandom secureRandom = new SecureRandom();
            keyPairGenerator.initialize(2048, secureRandom);
            
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            log.info("🔐 Generated secure RSA key pair (2048-bit)");
            
            return keyPair;
        } catch (NoSuchAlgorithmException e) {
            log.error("❌ Failed to generate RSA key pair", e);
            throw new RuntimeException("Unable to generate secure RSA key pair", e);
        }
    }
}
