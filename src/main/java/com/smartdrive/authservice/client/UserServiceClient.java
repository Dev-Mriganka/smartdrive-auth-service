package com.smartdrive.authservice.client;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;

/**
 * Client for communicating with User Service
 * Implements the Auth Service -> User Service calls from sequence diagram
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class UserServiceClient {

    private final RestTemplate restTemplate;
    
    @Value("${user.service.url:http://user-service:8083}")
    private String userServiceUrl;
    
    @Value("${auth.service.internal.key:internal-gateway-secret-key-2024-minimum-32-chars}")
    private String internalAuthKey;
    
    @Value("${gateway.signature.secret:signature-gateway-secret-key-2024-minimum-32-chars}")
    private String signatureSecret;

    /**
     * Verify user credentials (placeholder - not implemented in current flow)
     * In the current sequence diagram, Auth Service handles credentials directly
     */
    public boolean verifyCredentials(String email, String password) {
        log.info("🔐 Verifying credentials for user: {}", email);
        // In the current architecture, Auth Service handles credentials directly
        // This method is kept for compatibility but not used in the main flow
        return false;
    }

    /**
     * Get user token claims for JWT generation by email
     * This method finds the user by email first, then gets token claims
     */
    public Map<String, Object> getUserTokenClaims(String email) {
        log.info("👤 Getting token claims for user: {}", email);
        
        try {
            // First get user profile by email to get auth_user_id
            HttpHeaders headers = createGatewayHeaders(null, "/api/v1/users/profile/email/" + email);
            HttpEntity<Void> entity = new HttpEntity<>(headers);
            
            ResponseEntity<Map> profileResponse = restTemplate.exchange(
                userServiceUrl + "/api/v1/users/profile/email/" + email,
                HttpMethod.GET,
                entity,
                Map.class
            );
            
            if (!profileResponse.getStatusCode().is2xxSuccessful() || profileResponse.getBody() == null) {
                log.warn("⚠️ User profile not found for email: {}", email);
                return Map.of();
            }
            
            String authUserId = (String) profileResponse.getBody().get("authUserId");
            if (authUserId == null) {
                log.warn("⚠️ Auth user ID not found for email: {}", email);
                return Map.of();
            }
            
            // Now get token claims using auth_user_id
            return getUserTokenClaimsById(authUserId);
            
        } catch (Exception e) {
            log.error("❌ Error getting token claims for user: {}", email, e);
            return Map.of();
        }
    }

    /**
     * Get user token claims by auth user ID for JWT generation
     * This is the main method used during login flow as per sequence diagram
     */
    public Map<String, Object> getUserTokenClaimsById(String authUserId) {
        log.info("👤 Getting token claims for auth user ID: {}", authUserId);
        
        try {
            HttpHeaders headers = createGatewayHeaders(null, "/api/v1/users/profile-by-auth-id/" + authUserId + "/token-claims");
            
            HttpEntity<Void> entity = new HttpEntity<>(headers);
            
            ResponseEntity<Map> response = restTemplate.exchange(
                userServiceUrl + "/api/v1/users/profile-by-auth-id/" + authUserId + "/token-claims",
                HttpMethod.GET,
                entity,
                Map.class
            );
            
            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                log.info("✅ Retrieved token claims for auth user ID: {}", authUserId);
                return response.getBody();
            } else {
                log.warn("⚠️ Failed to get token claims for auth user ID: {}", authUserId);
                return Map.of();
            }
            
        } catch (Exception e) {
            log.error("❌ Error getting token claims for auth user ID: {}", authUserId, e);
            return Map.of();
        }
    }

    /**
     * Get user by email for social login
     */
    public Map<String, Object> getUserByEmail(String email) {
        log.info("🔍 Getting user by email: {}", email);
        
        try {
            HttpHeaders headers = createGatewayHeaders(null, "/api/v1/users/profile/email/" + email);
            
            HttpEntity<Void> entity = new HttpEntity<>(headers);
            
            ResponseEntity<Map> response = restTemplate.exchange(
                userServiceUrl + "/api/v1/users/profile/email/" + email,
                HttpMethod.GET,
                entity,
                Map.class
            );
            
            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                log.info("✅ Found user by email: {}", email);
                return response.getBody();
            } else {
                log.warn("⚠️ User not found by email: {}", email);
                return Map.of();
            }
            
        } catch (Exception e) {
            log.error("❌ Error getting user by email: {}", email, e);
            return Map.of();
        }
    }

    /**
     * Create user from Google OAuth2 profile (placeholder)
     */
    public Map<String, Object> createGoogleUser(Map<String, Object> userData) {
        log.info("👤 Creating user from Google OAuth2: {}", userData.get("email"));
        
        try {
            HttpHeaders headers = createGatewayHeaders(null, "/api/v1/users/google-register");
            
            HttpEntity<Map<String, Object>> entity = new HttpEntity<>(userData, headers);
            
            ResponseEntity<Map> response = restTemplate.exchange(
                userServiceUrl + "/api/v1/users/google-register",
                HttpMethod.POST,
                entity,
                Map.class
            );
            
            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                log.info("✅ Created user from Google OAuth2: {}", userData.get("email"));
                return response.getBody();
            } else {
                log.warn("⚠️ Failed to create user from Google OAuth2: {}", userData.get("email"));
                return Map.of();
            }
            
        } catch (Exception e) {
            log.error("❌ Error creating user from Google OAuth2: {}", userData.get("email"), e);
            return Map.of();
        }
    }

    /**
     * Link existing user account to Google OAuth2 (placeholder)
     */
    public Map<String, Object> linkGoogleAccount(String email, Map<String, Object> googleData) {
        log.info("🔗 Linking Google account for user: {}", email);
        
        try {
            HttpHeaders headers = createGatewayHeaders(null, "/api/v1/users/" + email + "/link-google");
            
            HttpEntity<Map<String, Object>> entity = new HttpEntity<>(googleData, headers);
            
            ResponseEntity<Map> response = restTemplate.exchange(
                userServiceUrl + "/api/v1/users/" + email + "/link-google",
                HttpMethod.PUT,
                entity,
                Map.class
            );
            
            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                log.info("✅ Successfully linked Google account for user: {}", email);
                return response.getBody();
            } else {
                log.warn("⚠️ Failed to link Google account for user: {}", email);
                return Map.of();
            }
            
        } catch (Exception e) {
            log.error("❌ Error linking Google account for user: {}", email, e);
            throw new RuntimeException("Failed to link Google account", e);
        }
    }
    
    /**
     * Get user profile by auth user ID for JWT generation
     * This is called during login to get complete user profile data
     */
    public Map<String, Object> getUserProfileByAuthId(String authUserId) {
        log.info("👤 Getting user profile for auth user ID: {}", authUserId);

        try {
            HttpHeaders headers = createGatewayHeaders(null, "/api/v1/users/profile-by-auth-id/" + authUserId);
            HttpEntity<Void> entity = new HttpEntity<>(headers);

            ResponseEntity<Map> response = restTemplate.exchange(
                userServiceUrl + "/api/v1/users/profile-by-auth-id/" + authUserId,
                HttpMethod.GET,
                entity,
                Map.class
            );

            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                log.info("✅ Retrieved user profile for auth user ID: {}", authUserId);
                return response.getBody();
            } else {
                log.warn("⚠️ User profile not found for auth user ID: {}", authUserId);
                return Map.of();
            }

        } catch (Exception e) {
            log.error("❌ Error getting user profile for auth user ID: {}", authUserId, e);
            return Map.of();
        }
    }

    /**
     * Create gateway headers with proper authentication and signature
     */
    private HttpHeaders createGatewayHeaders(String userId, String path) {
        HttpHeaders headers = new HttpHeaders();
        
        // Basic gateway headers
        headers.set("X-Internal-Auth", internalAuthKey);
        headers.set("X-Forwarded-By", "SmartDrive-Gateway");
        
        // Add timestamp
        String timestamp = String.valueOf(Instant.now().getEpochSecond());
        headers.set("X-Gateway-Timestamp", timestamp);
        
        // Generate and add signature
        String signature = generateSignature(userId, path, timestamp);
        headers.set("X-Gateway-Signature", signature);
        
        return headers;
    }
    
    /**
     * Generate HMAC signature for gateway authentication
     */
    private String generateSignature(String userId, String path, String timestamp) {
        try {
            String data = (userId != null ? userId : "") + "|" + path + "|" + timestamp;
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKeySpec = new SecretKeySpec(signatureSecret.getBytes(), "HmacSHA256");
            mac.init(secretKeySpec);
            byte[] signature = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(signature);
        } catch (Exception e) {
            log.error("❌ Failed to generate signature", e);
            return "invalid";
        }
    }
}