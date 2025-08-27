package com.smartdrive.authservice.service;

import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Refresh Token Service for managing JWT refresh tokens
 * 
 * Handles:
 * 1. Refresh token generation with optimized structure
 * 2. Token validation and expiry checking
 * 3. Token invalidation for security
 * 4. Username extraction from tokens
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class RefreshTokenService {
    
    private final JwtEncoder jwtEncoder;
    private final JwtDecoder jwtDecoder;
    
    // In production, use Redis or database for token storage
    private final ConcurrentHashMap<String, Boolean> invalidatedTokens = new ConcurrentHashMap<>();
    
    /**
     * Generate refresh token following your JWT structure specification:
     * {
     *   "sub": "user123",
     *   "token_type": "refresh",
     *   "iss": "smartdrive-auth-service", 
     *   "iat": 1703001600,
     *   "exp": 1705593600,
     *   "jti": "refresh-id-456"
     * }
     */
    public String generateRefreshToken(String username) {
        log.debug("🔄 Generating refresh token for user: {}", username);
        
        Instant now = Instant.now();
        Instant expiry = now.plusSeconds(86400 * 7); // 7 days
        
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("smartdrive-auth-service")
                .subject(username) // Use username as subject for refresh tokens
                .claim("token_type", "refresh")
                .issuedAt(now)
                .expiresAt(expiry)
                .id(UUID.randomUUID().toString()) // jti claim
                .build();
        
        String refreshToken = jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
        log.debug("✅ Refresh token generated successfully");
        
        return refreshToken;
    }
    
    /**
     * Validate refresh token
     * Checks:
     * 1. JWT signature and structure
     * 2. Token expiry
     * 3. Token type (must be "refresh")
     * 4. Token not in invalidated list
     */
    public boolean isValidRefreshToken(String refreshToken) {
        try {
            // Check if token is in invalidated list
            if (invalidatedTokens.containsKey(refreshToken)) {
                log.warn("❌ Refresh token is invalidated");
                return false;
            }
            
            // Decode and validate JWT
            var jwt = jwtDecoder.decode(refreshToken);
            
            // Check if token is expired
            if (jwt.getExpiresAt().isBefore(Instant.now())) {
                log.warn("❌ Refresh token is expired");
                return false;
            }
            
            // Check token type
            String tokenType = jwt.getClaimAsString("token_type");
            if (!"refresh".equals(tokenType)) {
                log.warn("❌ Invalid token type: {}", tokenType);
                return false;
            }
            
            log.debug("✅ Refresh token is valid");
            return true;
            
        } catch (JwtException e) {
            log.warn("❌ Invalid JWT refresh token: {}", e.getMessage());
            return false;
        } catch (Exception e) {
            log.error("❌ Error validating refresh token", e);
            return false;
        }
    }
    
    /**
     * Extract username from refresh token
     */
    public String getUsernameFromToken(String refreshToken) {
        try {
            var jwt = jwtDecoder.decode(refreshToken);
            String username = jwt.getSubject(); // Subject contains username for refresh tokens
            
            log.debug("✅ Extracted username from refresh token: {}", username);
            return username;
            
        } catch (Exception e) {
            log.error("❌ Error extracting username from refresh token", e);
            return null;
        }
    }
    
    /**
     * Invalidate refresh token (security best practice)
     * In production, store in Redis with TTL equal to token expiry
     */
    public void invalidateToken(String refreshToken) {
        try {
            invalidatedTokens.put(refreshToken, true);
            log.debug("🗑️ Refresh token invalidated successfully");
            
            // In production, also store in Redis:
            // redisTemplate.opsForValue().set("invalidated:" + refreshToken, "true", Duration.ofDays(7));
            
        } catch (Exception e) {
            log.error("❌ Error invalidating refresh token", e);
        }
    }
    
    /**
     * Clean up expired invalidated tokens (periodic cleanup)
     * In production, this would be handled by Redis TTL
     */
    public void cleanupExpiredTokens() {
        // This is a simplified implementation
        // In production, Redis TTL handles this automatically
        log.debug("🧹 Cleaning up expired invalidated tokens");
        
        invalidatedTokens.entrySet().removeIf(entry -> {
            try {
                var jwt = jwtDecoder.decode(entry.getKey());
                return jwt.getExpiresAt().isBefore(Instant.now());
            } catch (Exception e) {
                // If we can't decode it, it's probably expired or invalid
                return true;
            }
        });
    }
}
