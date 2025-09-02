package com.smartdrive.authservice.controller;

import com.smartdrive.authservice.client.UserServiceClient;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

/**
 * OAuth2 Controller for custom endpoints
 * Note: Most OAuth2 endpoints are handled by Spring Security OAuth2 Authorization Server
 */
@RestController
@RequestMapping("/oauth2")
@RequiredArgsConstructor
@Slf4j
public class OAuth2Controller {

    private final UserServiceClient userServiceClient;

    /**
     * Custom userinfo endpoint that works with our User Service
     */
    @GetMapping("/userinfo")
    public ResponseEntity<Map<String, Object>> getUserInfo() {
        log.info("👤 OAuth2 userinfo request");
        
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication == null || !authentication.isAuthenticated()) {
                return ResponseEntity.status(401).body(Map.of(
                    "error", "unauthorized",
                    "error_description", "User not authenticated"
                ));
            }
            
            Map<String, Object> userProfile = userServiceClient.getUserProfile(authentication.getName());
            if (userProfile.isEmpty()) {
                return ResponseEntity.status(404).body(Map.of(
                    "error", "user_not_found",
                    "error_description", "User profile not found"
                ));
            }
            
            // Format response according to OpenID Connect spec
            Map<String, Object> userInfo = new HashMap<>();
            userInfo.put("sub", userProfile.get("id"));
            userInfo.put("name", userProfile.get("firstName") + " " + userProfile.get("lastName"));
            userInfo.put("given_name", userProfile.get("firstName"));
            userInfo.put("family_name", userProfile.get("lastName"));
            userInfo.put("preferred_username", userProfile.get("username"));
            userInfo.put("email", userProfile.get("email"));
            userInfo.put("email_verified", userProfile.get("isEmailVerified"));
            userInfo.put("picture", userProfile.get("profilePictureUrl"));
            userInfo.put("updated_at", userProfile.get("updatedAt"));
            
            log.info("✅ Userinfo retrieved successfully for user: {}", authentication.getName());
            return ResponseEntity.ok(userInfo);
            
        } catch (Exception e) {
            log.error("❌ Error retrieving userinfo", e);
            return ResponseEntity.status(500).body(Map.of(
                "error", "server_error",
                "error_description", "Internal server error"
            ));
        }
    }

    /**
     * Health check endpoint for OAuth2 service
     */
    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> health() {
        Map<String, Object> health = new HashMap<>();
        health.put("status", "UP");
        health.put("service", "oauth2-authorization-server");
        health.put("timestamp", System.currentTimeMillis());
        return ResponseEntity.ok(health);
    }
}
