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
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class UserServiceClient {

    private final RestTemplate restTemplate;
    
    @Value("${user.service.url:http://user-service:8086}")
    private String userServiceUrl;
    
    @Value("${auth.service.internal.key:internal-auth-key}")
    private String internalAuthKey;
    
    @Value("${gateway.signature.secret:signature-secret-key-2024-minimum-32-chars}")
    private String signatureSecret;

    /**
     * Verify user credentials
     */
    public boolean verifyCredentials(String username, String password) {
        log.info("🔐 Verifying credentials for user: {}", username);
        
        try {
            HttpHeaders headers = createGatewayHeaders(null, "/api/v1/users/verify-credentials");
            
            Map<String, String> request = Map.of(
                "username", username,
                "password", password
            );
            
            HttpEntity<Map<String, String>> entity = new HttpEntity<>(request, headers);
            
            ResponseEntity<Map> response = restTemplate.exchange(
                userServiceUrl + "/api/v1/users/verify-credentials",
                HttpMethod.POST,
                entity,
                Map.class
            );
            
            boolean isValid = response.getStatusCode().is2xxSuccessful() && 
                            response.getBody() != null && 
                            Boolean.TRUE.equals(response.getBody().get("valid"));
            
            log.info("✅ Credential verification result for user {}: {}", username, isValid);
            return isValid;
            
        } catch (Exception e) {
            log.error("❌ Error verifying credentials for user: {}", username, e);
            return false;
        }
    }

    /**
     * Get user token claims for JWT generation
     */
    public Map<String, Object> getUserTokenClaims(String username) {
        log.info("👤 Getting token claims for user: {}", username);
        
        try {
            HttpHeaders headers = createGatewayHeaders(null, "/api/v1/users/" + username + "/token-claims");
            
            HttpEntity<Void> entity = new HttpEntity<>(headers);
            
            ResponseEntity<Map> response = restTemplate.exchange(
                userServiceUrl + "/api/v1/users/" + username + "/token-claims",
                HttpMethod.GET,
                entity,
                Map.class
            );
            
            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                log.info("✅ Retrieved token claims for user: {}", username);
                return response.getBody();
            } else {
                log.warn("⚠️ Failed to get token claims for user: {}", username);
                return Map.of();
            }
            
        } catch (Exception e) {
            log.error("❌ Error getting token claims for user: {}", username, e);
            return Map.of();
        }
    }

    /**
     * Get user token claims by user ID for JWT generation
     */
    public Map<String, Object> getUserTokenClaimsById(String userId) {
        log.info("👤 Getting token claims for user ID: {}", userId);
        
        try {
            HttpHeaders headers = createGatewayHeaders(null, "/api/v1/users/id/" + userId + "/token-claims");
            
            HttpEntity<Void> entity = new HttpEntity<>(headers);
            
            ResponseEntity<Map> response = restTemplate.exchange(
                userServiceUrl + "/api/v1/users/id/" + userId + "/token-claims",
                HttpMethod.GET,
                entity,
                Map.class
            );
            
            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                log.info("✅ Retrieved token claims for user ID: {}", userId);
                return response.getBody();
            } else {
                log.warn("⚠️ Failed to get token claims for user ID: {}", userId);
                return Map.of();
            }
            
        } catch (Exception e) {
            log.error("❌ Error getting token claims for user ID: {}", userId, e);
            return Map.of();
        }
    }

    /**
     * Get user by email for social login
     */
    public Map<String, Object> getUserByEmail(String email) {
        log.info("🔍 Getting user by email: {}", email);
        
        try {
            HttpHeaders headers = createGatewayHeaders(null, "/api/v1/users/email/" + email + "/token-claims");
            
            HttpEntity<Void> entity = new HttpEntity<>(headers);
            
            ResponseEntity<Map> response = restTemplate.exchange(
                userServiceUrl + "/api/v1/users/email/" + email + "/token-claims",
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
     * Create user from Google OAuth2 profile
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
     * Get user profile for userinfo endpoint
     */
    public Map<String, Object> getUserProfile(String username) {
        log.info("👤 Getting user profile for: {}", username);
        
        try {
            HttpHeaders headers = createGatewayHeaders(null, "/api/v1/users/" + username + "/profile");
            
            HttpEntity<Void> entity = new HttpEntity<>(headers);
            
            ResponseEntity<Map> response = restTemplate.exchange(
                userServiceUrl + "/api/v1/users/" + username + "/profile",
                HttpMethod.GET,
                entity,
                Map.class
            );
            
            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                log.info("✅ Retrieved user profile for: {}", username);
                return response.getBody();
            } else {
                log.warn("⚠️ Failed to get user profile for: {}", username);
                return Map.of();
            }
            
        } catch (Exception e) {
            log.error("❌ Error getting user profile for: {}", username, e);
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
