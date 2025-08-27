package com.smartdrive.authservice.controller;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.smartdrive.authservice.client.UserServiceClient;
import com.smartdrive.authservice.service.RefreshTokenService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Optimized Token Controller implementing your JWT structure specification
 * 
 * Handles:
 * 1. Token refresh flow (Step 3 of your auth flow)
 * 2. Optimized JWT structure with 30-minute expiry
 * 3. Proper refresh token management
 */
@RestController
@RequestMapping("/oauth2")
@RequiredArgsConstructor
@Slf4j
public class TokenController {
    
    private final JwtEncoder jwtEncoder;
    private final RefreshTokenService refreshTokenService;
    private final UserServiceClient userServiceClient;
    
    /**
     * Token refresh endpoint implementing Step 3 of your auth flow
     * Frontend (JWT expired) → API Gateway → Auth Server → Issue new JWT + Refresh Token
     */
    @PostMapping("/token/refresh")
    public ResponseEntity<Map<String, Object>> refreshToken(@RequestBody Map<String, String> request) {
        log.info("🔄 Token refresh request received");
        
        String refreshToken = request.get("refresh_token");
        
        try {
            // 1. Validate refresh token
            if (!refreshTokenService.isValidRefreshToken(refreshToken)) {
                log.warn("❌ Invalid or expired refresh token");
                return ResponseEntity.status(401).body(Map.of(
                    "error", "invalid_token",
                    "message", "Refresh token is invalid or expired"
                ));
            }
            
            // 2. Get user from refresh token
            String username = refreshTokenService.getUsernameFromToken(refreshToken);
            if (username == null) {
                log.warn("❌ Could not extract username from refresh token");
                return ResponseEntity.status(401).body(Map.of(
                    "error", "invalid_token",
                    "message", "Invalid refresh token format"
                ));
            }
            
            // 3. Generate new JWT + Refresh Token
            log.debug("🔄 Generating new tokens for user: {}", username);
            String newAccessToken = generateOptimizedAccessToken(username);
            String newRefreshToken = refreshTokenService.generateRefreshToken(username);
            
            // 4. Invalidate old refresh token (security best practice)
            refreshTokenService.invalidateToken(refreshToken);
            
            Map<String, Object> response = Map.of(
                "access_token", newAccessToken,
                "refresh_token", newRefreshToken,
                "token_type", "Bearer",
                "expires_in", 1800 // 30 minutes
            );
            
            log.info("✅ Token refresh successful for user: {}", username);
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            log.error("❌ Error refreshing token", e);
            return ResponseEntity.status(401).body(Map.of(
                "error", "invalid_token",
                "message", "Token refresh failed"
            ));
        }
    }
    
    /**
     * Generate optimized access token following your JWT structure specification:
     * {
     *   "sub": "user123",
     *   "username": "john.doe", 
     *   "email": "john@example.com",
     *   "roles": ["SMARTDRIVE_USER"],
     *   "iss": "smartdrive-auth-service",
     *   "iat": 1703001600,
     *   "exp": 1703003400,
     *   "jti": "jwt-id-123"
     * }
     */
    private String generateOptimizedAccessToken(String username) {
        // Get user claims from User Service
        Map<String, Object> claims = userServiceClient.getUserTokenClaims(username);
        
        Instant now = Instant.now();
        Instant expiry = now.plusSeconds(1800); // 30 minutes expiry
        
        JwtClaimsSet claimsSet = JwtClaimsSet.builder()
                .issuer("smartdrive-auth-service")
                .subject(claims.get("user_id").toString()) // Use user_id as subject
                .claim("username", claims.get("username"))
                .claim("email", claims.get("email"))
                .claim("roles", claims.get("roles"))
                .issuedAt(now)
                .expiresAt(expiry)
                .id(UUID.randomUUID().toString()) // jti claim
                .build();
                
        return jwtEncoder.encode(JwtEncoderParameters.from(claimsSet)).getTokenValue();
    }
}
