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
            
            // Map to audit format
            List<Map<String, Object>> auditData = users.stream()
                    .map(user -> {
                        Map<String, Object> userData = new HashMap<>();
                        userData.put("auth_user_id", user.getId());
                        userData.put("canonical_email", user.getEmail());
                        userData.put("email_verified", user.getEmailVerified());
                        userData.put("updated_at", user.getUpdatedAt());
                        return userData;
                    })
                    .collect(Collectors.toList());
            
            log.info("✅ Email audit data prepared - {} users", auditData.size());
            return ResponseEntity.ok(auditData);
            
        } catch (Exception e) {
            log.error("❌ Error processing email audit request", e);
            return ResponseEntity.status(500).build();
        }
    }

    /**
     * Get canonical user data by auth user ID
     * GET /api/internal/users/{authUserId}/canonical
     */
    @GetMapping("/users/{authUserId}/canonical")
    public ResponseEntity<Map<String, Object>> getCanonicalUserData(@PathVariable String authUserId) {
        log.info("📋 Internal canonical user data request - authUserId: {}", authUserId);
        
        try {
            AuthUser user = authUserRepository.findById(java.util.UUID.fromString(authUserId))
                    .orElse(null);
            
            if (user == null) {
                log.warn("⚠️ User not found for auth_user_id: {}", authUserId);
                return ResponseEntity.notFound().build();
            }
            
            Map<String, Object> canonicalData = new HashMap<>();
            canonicalData.put("auth_user_id", user.getId());
            canonicalData.put("canonical_email", user.getEmail());
            canonicalData.put("email_verified", user.getEmailVerified());
            canonicalData.put("account_locked", user.getAccountLocked());
            canonicalData.put("provider", user.getProvider());
            canonicalData.put("created_at", user.getCreatedAt());
            canonicalData.put("updated_at", user.getUpdatedAt());
            
            log.info("✅ Canonical user data retrieved for: {}", authUserId);
            return ResponseEntity.ok(canonicalData);
            
        } catch (Exception e) {
            log.error("❌ Error retrieving canonical user data", e);
            return ResponseEntity.status(500).build();
        }
    }

    /**
     * Bulk email verification status check
     * POST /api/internal/users/email-verification-status
     */
    @PostMapping("/users/email-verification-status")
    public ResponseEntity<Map<String, Object>> checkEmailVerificationStatus(
            @RequestBody Map<String, Object> request) {
        
        log.info("📋 Internal email verification status check");
        
        try {
            @SuppressWarnings("unchecked")
            List<String> authUserIds = (List<String>) request.get("auth_user_ids");
            
            if (authUserIds == null || authUserIds.isEmpty()) {
                return ResponseEntity.badRequest().build();
            }
            
            List<java.util.UUID> uuids = authUserIds.stream()
                    .map(java.util.UUID::fromString)
                    .collect(Collectors.toList());
            
            List<AuthUser> users = authUserRepository.findAllById(uuids);
            
            Map<String, Object> statusMap = new HashMap<>();
            for (AuthUser user : users) {
                Map<String, Object> userStatus = new HashMap<>();
                userStatus.put("email_verified", user.getEmailVerified());
                userStatus.put("email", user.getEmail());
                userStatus.put("account_locked", user.getAccountLocked());
                statusMap.put(user.getId().toString(), userStatus);
            }
            
            Map<String, Object> response = new HashMap<>();
            response.put("verification_status", statusMap);
            response.put("total_checked", users.size());
            
            log.info("✅ Email verification status checked for {} users", users.size());
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            log.error("❌ Error checking email verification status", e);
            return ResponseEntity.status(500).build();
        }
    }

    /**
     * Health check for internal endpoints
     */
    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> health() {
        Map<String, Object> response = new HashMap<>();
        response.put("status", "healthy");
        response.put("service", "auth-service-internal");
        response.put("timestamp", System.currentTimeMillis());
        return ResponseEntity.ok(response);
    }

    /**
     * Get user email by auth user ID (for consistency checks)
     * GET /api/v1/auth/users/{authUserId}/email
     */
    @GetMapping("/users/{authUserId}/email")
    public ResponseEntity<String> getUserEmail(@PathVariable String authUserId) {
        log.info("📧 Internal get user email - authUserId: {}", authUserId);
        
        try {
            AuthUser user = authUserRepository.findById(java.util.UUID.fromString(authUserId))
                    .orElse(null);
            
            if (user == null) {
                log.warn("⚠️ User not found for auth_user_id: {}", authUserId);
                return ResponseEntity.notFound().build();
            }
            
            log.info("✅ User email retrieved for: {}", authUserId);
            return ResponseEntity.ok(user.getEmail());
            
        } catch (Exception e) {
            log.error("❌ Error retrieving user email", e);
            return ResponseEntity.status(500).build();
        }
    }

    /**
     * Get user email verification status by auth user ID
     * GET /api/v1/auth/users/{authUserId}/email-verified
     */
    @GetMapping("/users/{authUserId}/email-verified")
    public ResponseEntity<Boolean> getUserEmailVerified(@PathVariable String authUserId) {
        log.info("✅ Internal get user email verification - authUserId: {}", authUserId);
        
        try {
            AuthUser user = authUserRepository.findById(java.util.UUID.fromString(authUserId))
                    .orElse(null);
            
            if (user == null) {
                log.warn("⚠️ User not found for auth_user_id: {}", authUserId);
                return ResponseEntity.notFound().build();
            }
            
            log.info("✅ User email verification status retrieved for: {}", authUserId);
            return ResponseEntity.ok(user.getEmailVerified());
            
        } catch (Exception e) {
            log.error("❌ Error retrieving user email verification status", e);
            return ResponseEntity.status(500).build();
        }
    }

    /**
     * Check if user exists by auth user ID
     * GET /api/v1/auth/users/{authUserId}/exists
     */
    @GetMapping("/users/{authUserId}/exists")
    public ResponseEntity<Boolean> userExists(@PathVariable String authUserId) {
        log.info("👤 Internal check user exists - authUserId: {}", authUserId);
        
        try {
            boolean exists = authUserRepository.existsById(java.util.UUID.fromString(authUserId));
            
            log.info("✅ User existence check for: {} - exists: {}", authUserId, exists);
            return ResponseEntity.ok(exists);
            
        } catch (Exception e) {
            log.error("❌ Error checking user existence", e);
            return ResponseEntity.status(500).build();
        }
    }

    /**
     * Get service statistics
     */
    @GetMapping("/stats")
    public ResponseEntity<Map<String, Object>> getStats() {
        log.info("📊 Internal stats request");
        
        try {
            long totalUsers = authUserRepository.count();
            long verifiedUsers = authUserRepository.countByEmailVerified(true);
            long lockedUsers = authUserRepository.countByAccountLocked(true);
            
            Map<String, Object> stats = new HashMap<>();
            stats.put("total_users", totalUsers);
            stats.put("verified_users", verifiedUsers);
            stats.put("unverified_users", totalUsers - verifiedUsers);
            stats.put("locked_users", lockedUsers);
            stats.put("verification_rate", totalUsers > 0 ? (double) verifiedUsers / totalUsers * 100 : 0);
            
            log.info("✅ Internal stats retrieved");
            return ResponseEntity.ok(stats);
            
        } catch (Exception e) {
            log.error("❌ Error retrieving internal stats", e);
            return ResponseEntity.status(500).build();
        }
    }
}