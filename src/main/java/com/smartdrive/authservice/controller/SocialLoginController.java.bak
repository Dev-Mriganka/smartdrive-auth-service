package com.smartdrive.authservice.controller;

import com.smartdrive.authservice.service.SocialLoginService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

/**
 * Controller for social login endpoints
 */
@RestController
@RequestMapping("/oauth2/social")
@RequiredArgsConstructor
@Slf4j
public class SocialLoginController {

    private final SocialLoginService socialLoginService;

    /**
     * Get authorization URL for social login
     */
    @GetMapping("/{provider}/authorize")
    public ResponseEntity<Map<String, Object>> getAuthorizationUrl(
            @PathVariable String provider,
            @RequestParam("redirect_uri") String redirectUri) {
        
        log.info("🔗 Getting authorization URL for provider: {}", provider);
        
        try {
            String authorizationUrl = socialLoginService.getAuthorizationUrl(provider, redirectUri);
            
            Map<String, Object> response = new HashMap<>();
            response.put("authorization_url", authorizationUrl);
            response.put("provider", provider);
            response.put("redirect_uri", redirectUri);
            
            log.info("✅ Authorization URL generated for provider: {}", provider);
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            log.error("❌ Error getting authorization URL for provider: {}", provider, e);
            return ResponseEntity.badRequest().body(Map.of(
                "error", "invalid_provider",
                "error_description", e.getMessage()
            ));
        }
    }

    /**
     * Process social login callback
     */
    @PostMapping("/{provider}/callback")
    public ResponseEntity<Map<String, Object>> processSocialLoginCallback(
            @PathVariable String provider,
            @RequestParam("code") String authorizationCode,
            @RequestParam("redirect_uri") String redirectUri) {
        
        log.info("🔄 Processing social login callback for provider: {}", provider);
        
        try {
            Map<String, Object> result = socialLoginService.processSocialLogin(provider, authorizationCode, redirectUri);
            
            log.info("✅ Social login processed successfully for provider: {}", provider);
            return ResponseEntity.ok(result);
            
        } catch (Exception e) {
            log.error("❌ Error processing social login for provider: {}", provider, e);
            return ResponseEntity.badRequest().body(Map.of(
                "error", "social_login_failed",
                "error_description", e.getMessage()
            ));
        }
    }

    /**
     * Get available social login providers
     */
    @GetMapping("/providers")
    public ResponseEntity<Map<String, Object>> getAvailableProviders() {
        log.info("📋 Getting available social login providers");
        
        Map<String, Object> providers = Map.of(
            "providers", Map.of(
                "google", Map.of(
                    "name", "Google",
                    "enabled", true,
                    "authorization_endpoint", "/oauth2/social/google/authorize"
                ),
                "github", Map.of(
                    "name", "GitHub",
                    "enabled", false,
                    "authorization_endpoint", "/oauth2/social/github/authorize"
                )
            )
        );
        
        return ResponseEntity.ok(providers);
    }
}
