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

    /**
     * Verify user credentials
     */
    public boolean verifyCredentials(String username, String password) {
        log.info("🔐 Verifying credentials for user: {}", username);
        
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.set("X-Internal-Auth", internalAuthKey);
            
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
            HttpHeaders headers = new HttpHeaders();
            headers.set("X-Internal-Auth", internalAuthKey);
            
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
     * Get user profile for userinfo endpoint
     */
    public Map<String, Object> getUserProfile(String username) {
        log.info("👤 Getting user profile for: {}", username);
        
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.set("X-Internal-Auth", internalAuthKey);
            
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
     * Find user by email
     */
    public Map<String, Object> findUserByEmail(String email) {
        log.info("🔍 Finding user by email: {}", email);
        
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.set("X-Internal-Auth", internalAuthKey);
            
            HttpEntity<Void> entity = new HttpEntity<>(headers);
            
            ResponseEntity<Map> response = restTemplate.exchange(
                userServiceUrl + "/api/v1/users/email/" + email,
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
            log.error("❌ Error finding user by email: {}", email, e);
            return Map.of();
        }
    }

    /**
     * Create user from social login
     */
    public Map<String, Object> createUserFromSocialLogin(Map<String, Object> userData) {
        log.info("👤 Creating user from social login: {}", userData.get("email"));
        
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.set("X-Internal-Auth", internalAuthKey);
            
            HttpEntity<Map<String, Object>> entity = new HttpEntity<>(userData, headers);
            
            ResponseEntity<Map> response = restTemplate.exchange(
                userServiceUrl + "/api/v1/users/social-login",
                HttpMethod.POST,
                entity,
                Map.class
            );
            
            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                log.info("✅ Created user from social login: {}", userData.get("email"));
                return response.getBody();
            } else {
                log.warn("⚠️ Failed to create user from social login: {}", userData.get("email"));
                return Map.of();
            }
            
        } catch (Exception e) {
            log.error("❌ Error creating user from social login: {}", userData.get("email"), e);
            return Map.of();
        }
    }

    /**
     * Link social account to existing user
     */
    public Map<String, Object> linkSocialAccount(Map<String, Object> socialAccountData) {
        log.info("🔗 Linking social account for user: {}", socialAccountData.get("userId"));
        
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.set("X-Internal-Auth", internalAuthKey);
            
            HttpEntity<Map<String, Object>> entity = new HttpEntity<>(socialAccountData, headers);
            
            ResponseEntity<Map> response = restTemplate.exchange(
                userServiceUrl + "/api/v1/users/link-social-account",
                HttpMethod.POST,
                entity,
                Map.class
            );
            
            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                log.info("✅ Linked social account for user: {}", socialAccountData.get("userId"));
                return response.getBody();
            } else {
                log.warn("⚠️ Failed to link social account for user: {}", socialAccountData.get("userId"));
                return Map.of();
            }
            
        } catch (Exception e) {
            log.error("❌ Error linking social account for user: {}", socialAccountData.get("userId"), e);
            return Map.of();
        }
    }
}
