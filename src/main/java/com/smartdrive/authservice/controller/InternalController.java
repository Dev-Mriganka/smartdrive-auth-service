package com.smartdrive.authservice.controller;

import com.smartdrive.authservice.model.AuthUser;
import com.smartdrive.authservice.repository.AuthUserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Internal API Controller for Auth Service
 * Handles internal service-to-service communication
 * Used for consistency checks and data synchronization
 */
@RestController
@RequestMapping("/api/internal")
@RequiredArgsConstructor
@Slf4j
public class InternalController {

    private final AuthUserRepository authUserRepository;

    /**
     * Email audit endpoint for consistency checks
     * GET /api/internal/users/email-audit
     * Used by User Service to verify email consistency
     */
    @GetMapping("/users/email-audit")
    public ResponseEntity<List<Map<String, Object>>> getEmailAudit(
            @RequestParam(required = false) String since) {
        
        log.info("📋 Internal email audit request - since: {}", since);
        
        try {
            List<AuthUser> users;
            
            if (since != null && !since.trim().isEmpty()) {
                // Get users updated since the specified date
                LocalDateTime sinceDate = LocalDateTime.parse(since);
                users = authUserRepository.findByUpdatedAtAfter(sinceDate);
                log.debug("Found {} users updated since {}", users.size(), sinceDate);
            } else {
                // Get all users (for full audit)
                users = authUserRepository.findAll();
                log.debug("Found {} total users for audit", users.size());
            }
            
            // Convert to audit format with canonical email data
            List<Map<String, Object>> auditData = users.stream()
                    .map(user -> {
                        Map<String, Object> userData = new HashMap<>();
                        userData.put("auth_user_id", user.getId().toString());
                        userData.put("canonical_email", user.getEmail()); // Canonical email from Auth Service
                        userData.put("email_verified", user.getEmailVerified());
                        userData.put("provider", user.getProvider());
                        userData.put("updated_at", user.getUpdatedAt());
                        return userData;
                    })
                    .collect(Collectors.toList());
            
            log.info("✅ Email audit completed - returned {} user records", auditData.size());
            return ResponseEntity.ok(auditData);
            
        } catch (Exception e) {
            log.error("❌ Email audit failed", e);
            return ResponseEntity.internalServerError().build();
        }
    }

    /**
     * Get user authentication status by ID
     * GET /api/internal/users/{userId}/auth-status
     * Used by other services to check if user is enabled/verified
     */
    @GetMapping("/users/{userId}/auth-status")
    public ResponseEntity<Map<String, Object>> getUserAuthStatus(@PathVariable String userId) {
        log.info("🔍 Internal auth status request for user: {}", userId);

        try {
            AuthUser user = authUserRepository.findById(java.util.UUID.fromString(userId))
                    .orElse(null);
            
            if (user == null) {
                log.warn("❌ User not found for auth status check: {}", userId);
                return ResponseEntity.notFound().build();
            }
            
            Map<String, Object> authStatus = new HashMap<>();
            authStatus.put("user_id", user.getId().toString());
            authStatus.put("email", user.getEmail());
            authStatus.put("email_verified", user.getEmailVerified());
            authStatus.put("account_locked", user.isLocked());
            authStatus.put("provider", user.getProvider());
            authStatus.put("failed_login_attempts", user.getFailedLoginAttempts());
            authStatus.put("created_at", user.getCreatedAt());
            authStatus.put("updated_at", user.getUpdatedAt());

            log.debug("✅ Auth status retrieved for user: {}", userId);
            return ResponseEntity.ok(authStatus);

        } catch (Exception e) {
            log.error("❌ Failed to get auth status for user: {}", userId, e);
            return ResponseEntity.internalServerError().build();
        }
    }

    /**
     * Batch user lookup by email
     * POST /api/internal/users/batch-lookup
     * Used by other services to lookup multiple users by email
     */
    @PostMapping("/users/batch-lookup")
    public ResponseEntity<List<Map<String, Object>>> batchUserLookup(
            @RequestBody Map<String, Object> lookupRequest) {

        log.info("🔍 Internal batch user lookup request");

        try {
            @SuppressWarnings("unchecked")
            List<String> emails = (List<String>) lookupRequest.get("emails");

            if (emails == null || emails.isEmpty()) {
                log.warn("❌ No emails provided for batch lookup");
                return ResponseEntity.badRequest().build();
            }
            
            // Normalize emails to lowercase
            List<String> normalizedEmails = emails.stream()
                    .map(email -> email.toLowerCase().trim())
                    .collect(Collectors.toList());
            
            List<AuthUser> users = authUserRepository.findByEmailIn(normalizedEmails);

            List<Map<String, Object>> userList = users.stream()
                    .map(user -> {
                        Map<String, Object> userData = new HashMap<>();
                        userData.put("auth_user_id", user.getId().toString());
                        userData.put("email", user.getEmail());
                        userData.put("email_verified", user.getEmailVerified());
                        userData.put("account_locked", user.isLocked());
                        userData.put("provider", user.getProvider());
                        return userData;
                    })
                    .collect(Collectors.toList());

            log.info("✅ Batch lookup completed - found {} users out of {} emails",
                    userList.size(), emails.size());
            return ResponseEntity.ok(userList);

        } catch (Exception e) {
            log.error("❌ Batch user lookup failed", e);
            return ResponseEntity.internalServerError().build();
        }
    }

    /**
     * Health check endpoint for internal monitoring
     * GET /api/internal/health
     */
    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> healthCheck() {
        Map<String, Object> health = new HashMap<>();
        health.put("status", "UP");
        health.put("service", "auth-service");
        health.put("timestamp", java.time.Instant.now());

        try {
            // Test database connectivity
            long userCount = authUserRepository.count();
            health.put("database", "UP");
            health.put("user_count", userCount);
        } catch (Exception e) {
            health.put("database", "DOWN");
            health.put("database_error", e.getMessage());
        }

        return ResponseEntity.ok(health);
    }
}