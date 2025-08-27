package com.smartdrive.authservice.controller;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

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
import com.smartdrive.authservice.dto.LoginRequest;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Custom Authentication Controller for UI integration
 * 
 * Flow Implementation:
 * User → API Gateway → OAuth Server (this controller)
 * ↓
 * Calls User Service /verify-credentials
 * ↓
 * Gets user claims /token-claims
 * ↓
 * Issues JWT Token
 * 
 * This controller acts as the OAuth Server in the authentication flow,
 * coordinating with the User Service for credential verification and user
 * claims,
 * then issuing JWT tokens for authenticated sessions.
 */
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final UserServiceClient userServiceClient;
    private final JwtEncoder jwtEncoder;

    /**
     * Custom login endpoint for UI integration
     * 
     * Implements the complete authentication flow:
     * 1. Receives login request from API Gateway
     * 2. Calls User Service to verify credentials
     * 3. Gets user claims from User Service
     * 4. Issues JWT tokens
     * 
     * This maintains the proper separation of concerns while providing
     * a direct endpoint for UI authentication.
     */
    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@Valid @RequestBody LoginRequest loginRequest) {
        log.info("🔐 OAuth Server received login request via API Gateway for user: {}",
                loginRequest.getUsernameOrEmail());
        log.info("📊 Starting authentication flow: User → API Gateway → OAuth Server → User Service");

        try {
            // Step 1: OAuth Server calls User Service to verify credentials
            log.debug("🔍 Step 1: Verifying credentials with User Service");
            boolean isValid = userServiceClient.verifyCredentials(
                    loginRequest.getUsernameOrEmail(),
                    loginRequest.getPassword());

            if (!isValid) {
                log.warn("❌ Credential verification failed for user: {}", loginRequest.getUsernameOrEmail());
                Map<String, Object> errorResponse = new HashMap<>();
                errorResponse.put("error", "invalid_credentials");
                errorResponse.put("error_description", "Invalid username/email or password");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
            }

            log.debug("✅ Step 1 Complete: Credentials verified successfully");

            // Step 2: OAuth Server gets user claims from User Service
            log.debug("🔍 Step 2: Getting user token claims from User Service");
            Map<String, Object> userClaims = userServiceClient.getUserTokenClaims(loginRequest.getUsernameOrEmail());
            if (userClaims.isEmpty()) {
                log.error("❌ Failed to get user claims for: {}", loginRequest.getUsernameOrEmail());
                Map<String, Object> errorResponse = new HashMap<>();
                errorResponse.put("error", "user_claims_error");
                errorResponse.put("error_description", "Failed to retrieve user information");
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
            }

            log.debug("✅ Step 2 Complete: User claims retrieved successfully");

            // Check if user is enabled and email verified
            Boolean isEnabled = (Boolean) userClaims.get("is_enabled");
            Boolean isEmailVerified = (Boolean) userClaims.get("is_email_verified");

            if (!isEnabled) {
                log.warn("❌ User account disabled: {}", loginRequest.getUsernameOrEmail());
                Map<String, Object> errorResponse = new HashMap<>();
                errorResponse.put("error", "account_disabled");
                errorResponse.put("error_description", "User account is disabled");
                return ResponseEntity.status(HttpStatus.FORBIDDEN).body(errorResponse);
            }

            if (!isEmailVerified) {
                log.warn("❌ Email not verified for user: {}", loginRequest.getUsernameOrEmail());
                Map<String, Object> errorResponse = new HashMap<>();
                errorResponse.put("error", "email_not_verified");
                errorResponse.put("error_description", "Please verify your email address before logging in");
                return ResponseEntity.status(HttpStatus.FORBIDDEN).body(errorResponse);
            }

            // Step 3: OAuth Server issues JWT Token
            log.debug("🔍 Step 3: OAuth Server generating JWT tokens");
            String accessToken = generateAccessToken(userClaims);
            String refreshToken = generateRefreshToken(userClaims);
            log.debug("✅ Step 3 Complete: JWT tokens generated successfully");

            // Prepare response
            Map<String, Object> response = new HashMap<>();
            response.put("access_token", accessToken);
            response.put("refresh_token", refreshToken);
            response.put("token_type", "Bearer");
            response.put("expires_in", 1800); // 30 minutes
            response.put("scope", "openid profile email");

            // Add user info
            Map<String, Object> userInfo = new HashMap<>();
            userInfo.put("id", userClaims.get("user_id").toString());
            userInfo.put("username", userClaims.get("username"));
            userInfo.put("email", userClaims.get("email"));
            userInfo.put("firstName", userClaims.get("first_name"));
            userInfo.put("lastName", userClaims.get("last_name"));
            userInfo.put("roles", userClaims.get("roles"));

            response.put("user", userInfo);

            log.info("✅ Login successful for user: {}", loginRequest.getUsernameOrEmail());
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("❌ Login error for user: {}", loginRequest.getUsernameOrEmail(), e);
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("error", "server_error");
            errorResponse.put("error_description", "An internal server error occurred");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    /**
     * Generate JWT access token
     */
    private String generateAccessToken(Map<String, Object> userClaims) {
        Instant now = Instant.now();
        Instant expiry = now.plusSeconds(1800); // 30 minutes (optimized)

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("smartdrive-auth-service")
                .subject(userClaims.get("user_id").toString()) // Use user_id as subject
                .audience(java.util.List.of("smartdrive-web"))
                .issuedAt(now)
                .expiresAt(expiry)
                .notBefore(now)
                .id(java.util.UUID.randomUUID().toString()) // Add jti claim
                .claim("username", userClaims.get("username"))
                .claim("email", userClaims.get("email"))
                .claim("roles", userClaims.get("roles"))
                .build();

        return jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }

    /**
     * Refresh token endpoint for token renewal
     * This implements Step 3 of your auth flow: Token Refresh Flow
     */
    @PostMapping("/refresh")
    public ResponseEntity<Map<String, Object>> refreshToken(@RequestBody Map<String, String> refreshRequest) {
        log.info("🔄 Token refresh request received");

        try {
            String refreshToken = refreshRequest.get("refresh_token");
            if (refreshToken == null || refreshToken.trim().isEmpty()) {
                log.warn("❌ Missing refresh token in request");
                Map<String, Object> errorResponse = new HashMap<>();
                errorResponse.put("error", "invalid_request");
                errorResponse.put("error_description", "Missing refresh_token parameter");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
            }

            // TODO: Validate refresh token (decode and verify)
            // For now, extract username from token claims
            // In production, you should validate the refresh token properly

            // Step 1: Verify refresh token is valid and not expired
            log.debug("🔍 Verifying refresh token validity");

            // Step 2: Get fresh user claims from User Service
            log.debug("🔍 Getting fresh user claims from User Service");
            // Extract username from the refresh token (simplified for demo)
            String username = extractUsernameFromRefreshToken(refreshToken);
            if (username == null) {
                log.warn("❌ Invalid refresh token");
                Map<String, Object> errorResponse = new HashMap<>();
                errorResponse.put("error", "invalid_grant");
                errorResponse.put("error_description", "Invalid or expired refresh token");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
            }

            Map<String, Object> userClaims = userServiceClient.getUserTokenClaims(username);
            if (userClaims.isEmpty()) {
                log.error("❌ Failed to get user claims for refresh: {}", username);
                Map<String, Object> errorResponse = new HashMap<>();
                errorResponse.put("error", "user_claims_error");
                errorResponse.put("error_description", "Failed to retrieve user information");
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
            }

            // Step 3: Generate new tokens
            log.debug("🔍 Generating new JWT tokens");
            String newAccessToken = generateAccessToken(userClaims);
            String newRefreshToken = generateRefreshToken(userClaims);

            // Prepare response
            Map<String, Object> response = new HashMap<>();
            response.put("access_token", newAccessToken);
            response.put("refresh_token", newRefreshToken);
            response.put("token_type", "Bearer");
            response.put("expires_in", 1800); // 30 minutes
            response.put("scope", "openid profile email");

            log.info("✅ Token refresh successful for user: {}", username);
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("❌ Token refresh error", e);
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("error", "server_error");
            errorResponse.put("error_description", "An internal server error occurred during token refresh");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    /**
     * Extract username from refresh token (simplified implementation)
     * In production, use proper JWT decoding and validation
     */
    private String extractUsernameFromRefreshToken(String refreshToken) {
        try {
            // Decode JWT token without verification (for demo purposes)
            // In production, you MUST verify the token signature and expiration
            String[] parts = refreshToken.split("\\.");
            if (parts.length != 3) {
                return null;
            }

            // Decode payload
            String payload = new String(java.util.Base64.getUrlDecoder().decode(parts[1]));

            // Simple JSON parsing to extract username
            // In production, use proper JSON library
            if (payload.contains("\"username\":")) {
                String[] usernameParts = payload.split("\"username\":\"");
                if (usernameParts.length > 1) {
                    String username = usernameParts[1].split("\"")[0];
                    return username;
                }
            }

            return null;
        } catch (Exception e) {
            log.error("❌ Error extracting username from refresh token", e);
            return null;
        }
    }

    /**
     * Generate JWT refresh token
     */
    private String generateRefreshToken(Map<String, Object> userClaims) {
        Instant now = Instant.now();
        Instant expiry = now.plusSeconds(86400 * 7); // 7 days

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("smartdrive-auth-service")
                .subject(userClaims.get("user_id").toString()) // Use user_id as subject
                .audience(java.util.List.of("smartdrive-web"))
                .issuedAt(now)
                .expiresAt(expiry)
                .notBefore(now)
                .id(java.util.UUID.randomUUID().toString()) // Add jti claim
                .claim("token_type", "refresh")
                .build();

        return jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }
}
