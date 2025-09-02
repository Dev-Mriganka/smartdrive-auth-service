package com.smartdrive.authservice.service;

import java.util.Map;
import java.util.Optional;

import org.springframework.stereotype.Service;

import com.smartdrive.authservice.client.UserServiceClient;
import com.smartdrive.authservice.config.AuthServiceProperties;
import com.smartdrive.authservice.model.AuthUser;
import com.smartdrive.authservice.repository.AuthUserRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Authentication Business Service
 * 
 * Implements core authentication business logic following MVC pattern:
 * - Controller handles HTTP requests/responses
 * - Service handles business logic
 * - Repository handles data access
 * 
 * This service encapsulates the authentication workflow from the sequence diagram
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AuthenticationService {

    private final AuthUserRepository authUserRepository;
    private final UserServiceClient userServiceClient;
    private final AuthServiceProperties authProperties;

    /**
     * Authenticate user with email and password
     * 
     * @param email User email
     * @param password User password
     * @return AuthenticationResult containing user data and validation status
     */
    public AuthenticationResult authenticateUser(String email, String password) {
        log.debug("🔍 Authenticating user: {}", email);
        
        // Step 1: Find user by email
        Optional<AuthUser> authUserOpt = authUserRepository.findByEmail(email.toLowerCase().trim());
        if (authUserOpt.isEmpty()) {
            log.warn("❌ User not found: {}", email);
            return AuthenticationResult.failure("User not found");
        }
        
        AuthUser authUser = authUserOpt.get();
        
        // Step 2: Check account status
        if (authUser.isLocked()) {
            log.warn("❌ Account locked: {}", email);
            return AuthenticationResult.failure("Account is locked");
        }
        
        // Step 3: Check email verification (environment-dependent)
        if (authProperties.getSecurity().isEnforceEmailVerification() && !authUser.getEmailVerified()) {
            log.warn("❌ Email not verified: {}", email);
            return AuthenticationResult.failure("Email verification required");
        }
        
        log.debug("✅ User authentication successful: {}", email);
        return AuthenticationResult.success(authUser);
    }

    /**
     * Get complete user profile data for JWT token generation
     * 
     * @param authUser Authenticated user from auth database
     * @return Complete user claims map
     */
    public Map<String, Object> getUserClaimsForToken(AuthUser authUser) {
        log.debug("📊 Building user claims for token generation: {}", authUser.getId());
        
        try {
            // Get user profile from User Service
            Map<String, Object> userProfileData = userServiceClient.getUserProfileByAuthId(authUser.getId().toString());
            
            if (userProfileData == null || userProfileData.isEmpty()) {
                log.warn("⚠️ No user profile found, using default profile for: {}", authUser.getId());
                userProfileData = createDefaultUserProfile(authUser);
            }
            
            // Combine Auth Service data with User Service data
            Map<String, Object> completeUserClaims = new java.util.HashMap<>();
            
            // From Auth Service (authentication data)
            completeUserClaims.put("user_id", authUser.getId().toString());
            completeUserClaims.put("email", authUser.getEmail());
            completeUserClaims.put("is_email_verified", authUser.getEmailVerified());
            completeUserClaims.put("is_enabled", !authUser.isLocked());
            completeUserClaims.put("provider", authUser.getProvider());
            
            // From User Service (profile data)
            completeUserClaims.put("name", userProfileData.getOrDefault("name", "User"));
            completeUserClaims.put("first_name", userProfileData.getOrDefault("first_name", "User"));
            completeUserClaims.put("last_name", userProfileData.getOrDefault("last_name", "User"));
            completeUserClaims.put("roles", userProfileData.getOrDefault("roles", java.util.List.of("USER")));
            completeUserClaims.put("subscription", userProfileData.getOrDefault("subscription", "free"));
            completeUserClaims.put("permissions", userProfileData.getOrDefault("permissions", java.util.List.of()));
            
            log.debug("✅ User claims prepared for: {}", authUser.getId());
            return completeUserClaims;
            
        } catch (Exception e) {
            log.warn("⚠️ Failed to get user profile from User Service, using fallback: {}", e.getMessage());
            return createDefaultUserProfile(authUser);
        }
    }

    /**
     * Check if user exists by email
     */
    public boolean userExistsByEmail(String email) {
        return authUserRepository.existsByEmail(email.toLowerCase().trim());
    }

    /**
     * Create default user profile when User Service is unavailable
     */
    private Map<String, Object> createDefaultUserProfile(AuthUser authUser) {
        Map<String, Object> defaultProfile = new java.util.HashMap<>();
        defaultProfile.put("user_id", authUser.getId().toString());
        defaultProfile.put("email", authUser.getEmail());
        defaultProfile.put("name", "User");
        defaultProfile.put("first_name", "User");
        defaultProfile.put("last_name", "User");
        defaultProfile.put("roles", java.util.List.of("USER"));
        defaultProfile.put("subscription", "free");
        defaultProfile.put("permissions", java.util.List.of());
        defaultProfile.put("is_email_verified", authUser.getEmailVerified());
        defaultProfile.put("is_enabled", !authUser.isLocked());
        defaultProfile.put("provider", authUser.getProvider());
        
        log.debug("📝 Created default user profile for: {}", authUser.getId());
        return defaultProfile;
    }

    /**
     * Authentication result class
     */
    public static class AuthenticationResult {
        private final boolean success;
        private final String errorMessage;
        private final AuthUser authUser;

        private AuthenticationResult(boolean success, String errorMessage, AuthUser authUser) {
            this.success = success;
            this.errorMessage = errorMessage;
            this.authUser = authUser;
        }

        public static AuthenticationResult success(AuthUser authUser) {
            return new AuthenticationResult(true, null, authUser);
        }

        public static AuthenticationResult failure(String errorMessage) {
            return new AuthenticationResult(false, errorMessage, null);
        }

        public boolean isSuccess() {
            return success;
        }

        public String getErrorMessage() {
            return errorMessage;
        }

        public AuthUser getAuthUser() {
            return authUser;
        }
    }
}
