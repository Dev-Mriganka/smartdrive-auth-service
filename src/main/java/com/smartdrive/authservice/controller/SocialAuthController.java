package com.smartdrive.authservice.controller;

import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.smartdrive.authservice.service.SocialAuthService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Controller for social authentication (Google OAuth2)
 * Handles Google login flow and token exchange
 */
@RestController
@RequestMapping("/api/v1/auth/social")
@RequiredArgsConstructor
@Slf4j
public class SocialAuthController {

    private final SocialAuthService socialAuthService;

    /**
     * Get Google OAuth2 authorization URL
     * This starts the Google login flow by providing the authorization URL
     */
    @GetMapping("/google/login-url")
    public ResponseEntity<Map<String, Object>> getGoogleLoginUrl(
            @RequestParam(required = false, defaultValue = "http://localhost:3000/auth/callback") String redirectUri) {

        log.info("🔗 Generating Google OAuth2 login URL with redirect: {}", redirectUri);

        try {
            String authorizationUrl = socialAuthService.getGoogleAuthorizationUrl(redirectUri);

            Map<String, Object> response = Map.of(
                    "authorization_url", authorizationUrl,
                    "state", "google_oauth2_" + System.currentTimeMillis());

            log.info("✅ Google OAuth2 authorization URL generated successfully");
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("❌ Error generating Google OAuth2 URL", e);
            Map<String, Object> errorResponse = Map.of(
                    "error", "oauth2_url_error",
                    "error_description", "Failed to generate Google OAuth2 authorization URL");
            return ResponseEntity.internalServerError().body(errorResponse);
        }
    }

    /**
     * Handle Google OAuth2 callback
     * Exchanges authorization code for access token and creates/logs in user
     */
    @PostMapping("/google/callback")
    public ResponseEntity<Map<String, Object>> handleGoogleCallback(
            @RequestBody Map<String, String> callbackData) {

        String authorizationCode = callbackData.get("code");
        String state = callbackData.get("state");

        log.info("🔄 Processing Google OAuth2 callback with state: {}", state);

        if (authorizationCode == null || authorizationCode.trim().isEmpty()) {
            log.warn("❌ Missing authorization code in Google callback");
            Map<String, Object> errorResponse = Map.of(
                    "error", "invalid_request",
                    "error_description", "Missing authorization code");
            return ResponseEntity.badRequest().body(errorResponse);
        }

        try {
            Map<String, Object> authResult = socialAuthService.processGoogleCallback(authorizationCode);

            log.info("✅ Google OAuth2 login successful for user: {}",
                    authResult.get("user") != null ? ((Map<String, Object>) authResult.get("user")).get("email")
                            : "unknown");

            return ResponseEntity.ok(authResult);

        } catch (Exception e) {
            log.error("❌ Google OAuth2 callback processing failed", e);
            Map<String, Object> errorResponse = Map.of(
                    "error", "oauth2_callback_error",
                    "error_description", "Failed to process Google OAuth2 callback: " + e.getMessage());
            return ResponseEntity.internalServerError().body(errorResponse);
        }
    }

    /**
     * Handle Google OAuth2 callback via GET (for direct browser redirects)
     */
    @GetMapping("/google/callback")
    public ResponseEntity<String> handleGoogleCallbackGet(
            @RequestParam("code") String authorizationCode,
            @RequestParam(required = false) String state,
            @RequestParam(required = false) String error) {

        log.info("🔄 Processing Google OAuth2 GET callback");

        if (error != null) {
            log.warn("❌ Google OAuth2 error: {}", error);
            return ResponseEntity.badRequest().body(
                    "<!DOCTYPE html><html><body><h2>Login Error</h2><p>Google OAuth2 error: " + error
                            + "</p></body></html>");
        }

        if (authorizationCode == null || authorizationCode.trim().isEmpty()) {
            log.warn("❌ Missing authorization code in Google GET callback");
            return ResponseEntity.badRequest().body(
                    "<!DOCTYPE html><html><body><h2>Login Error</h2><p>Missing authorization code</p></body></html>");
        }

        try {
            Map<String, Object> authResult = socialAuthService.processGoogleCallback(authorizationCode);

            // Redirect to frontend with tokens in URL parameters
            String frontendUrl = String.format(
                    "http://localhost:5174/auth/google/callback?access_token=%s&refresh_token=%s&email=%s",
                    authResult.get("access_token"),
                    authResult.get("refresh_token"),
                    ((Map<String, Object>) authResult.get("user")).get("email"));

            return ResponseEntity.status(302)
                    .header("Location", frontendUrl)
                    .build();

        } catch (Exception e) {
            log.error("❌ Google OAuth2 GET callback processing failed", e);
            return ResponseEntity.internalServerError().body(
                    "<!DOCTYPE html><html><body><h2>Login Error</h2><p>Failed to process Google login: " +
                            e.getMessage() + "</p></body></html>");
        }
    }
}
