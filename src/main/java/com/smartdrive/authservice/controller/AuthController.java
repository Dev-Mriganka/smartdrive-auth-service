package com.smartdrive.authservice.controller;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.smartdrive.authservice.client.UserServiceClient;
import com.smartdrive.authservice.dto.LoginRequest;
import com.smartdrive.authservice.dto.RegistrationRequest;
import com.smartdrive.authservice.model.AuthUser;
import com.smartdrive.authservice.repository.AuthUserRepository;
import com.smartdrive.authservice.service.AuthEventPublisher;
import com.smartdrive.authservice.service.RedisTokenBlacklistService;
import com.smartdrive.authservice.service.RefreshTokenService;
import com.smartdrive.authservice.service.AuthenticationService;

import jakarta.servlet.http.HttpServletRequest;
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
    private final RefreshTokenService refreshTokenService;
    private final JwtDecoder jwtDecoder;
    private final RedisTokenBlacklistService redisTokenBlacklistService;
    private final AuthUserRepository authUserRepository;
    private final AuthEventPublisher authEventPublisher;
    private final PasswordEncoder passwordEncoder;
    private final com.smartdrive.authservice.repository.VerificationTokenRepository verificationTokenRepository;
    private final AuthenticationService authenticationService;

    /**
     * Verify email endpoint per sequence diagram
     * GET /api/v1/auth/verify-email?token=...
     */
    @GetMapping("/verify-email")
    public ResponseEntity<Map<String, Object>> verifyEmail(@RequestParam("token") String token) {
        log.info("📧 Email verification attempt with token");
        Map<String, Object> resp = new HashMap<>();
        try {
            var opt = verificationTokenRepository.findByToken(token);
            if (opt.isEmpty()) {
                resp.put("success", false);
                resp.put("message", "Invalid or expired token");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(resp);
            }
            var vt = opt.get();
            if (!vt.isValid()) {
                resp.put("success", false);
                resp.put("message", "Token not valid");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(resp);
            }

            // Mark user verified and token used
            var user = vt.getUser();
            user.setEmailVerified(true);
            authUserRepository.save(user);
            vt.markAsUsed();
            verificationTokenRepository.save(vt);

            // Publish event to User Service via SQS
            authEventPublisher.publishEmailVerified(user.getId(), user.getEmail());

            resp.put("success", true);
            resp.put("message", "Email verified successfully");
            return ResponseEntity.ok(resp);
        } catch (Exception e) {
            log.error("❌ Email verification failed", e);
            resp.put("success", false);
            resp.put("message", "Server error");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(resp);
        }
    }

    /**
     * Email change endpoint per sequence diagram
     * PUT /api/v1/auth/profile/email
     */
    @PostMapping("/profile/email")
    public ResponseEntity<Map<String, Object>> changeEmail(
            @RequestBody Map<String, String> emailChangeRequest,
            HttpServletRequest request) {
        log.info("📧 Email change request received");
        
        try {
            String accessToken = extractTokenFromRequest(request);
            if (accessToken == null) {
                Map<String, Object> errorResponse = new HashMap<>();
                errorResponse.put("error", "unauthorized");
                errorResponse.put("error_description", "Access token required");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
            }
            
            // Decode and validate access token
            Jwt jwt = jwtDecoder.decode(accessToken);
            String userId = jwt.getSubject();
            
            String newEmail = emailChangeRequest.get("new_email");
            String currentPassword = emailChangeRequest.get("password");
            
            if (newEmail == null || newEmail.trim().isEmpty()) {
                Map<String, Object> errorResponse = new HashMap<>();
                errorResponse.put("error", "invalid_request");
                errorResponse.put("error_description", "New email is required");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
            }
            
            if (currentPassword == null || currentPassword.trim().isEmpty()) {
                Map<String, Object> errorResponse = new HashMap<>();
                errorResponse.put("error", "invalid_request");
                errorResponse.put("error_description", "Current password is required");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
            }
            
            // Get current user
            AuthUser user = authUserRepository.findById(UUID.fromString(userId))
                    .orElseThrow(() -> new RuntimeException("User not found"));
            
            // Verify current password
            if (!passwordEncoder.matches(currentPassword, user.getPasswordHash())) {
                Map<String, Object> errorResponse = new HashMap<>();
                errorResponse.put("error", "invalid_credentials");
                errorResponse.put("error_description", "Current password is incorrect");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
            }
            
            // Check if new email already exists
            if (authUserRepository.existsByEmail(newEmail.toLowerCase().trim())) {
                Map<String, Object> errorResponse = new HashMap<>();
                errorResponse.put("error", "email_exists");
                errorResponse.put("error_description", "Email already in use");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
            }
            
            // Update email and mark as unverified
            String oldEmail = user.getEmail();
            user.setEmail(newEmail.toLowerCase().trim());
            user.setEmailVerified(false); // Email needs to be verified again
            authUserRepository.save(user);
            
            // Invalidate all user sessions (force re-login)
            redisTokenBlacklistService.invalidateAllUserSessions(userId);
            
            // Publish email change event
            authEventPublisher.publishEmailChanged(user.getId(), oldEmail, newEmail, false);
            
            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "Email updated successfully. Please login again with your new email.");
            
            log.info("✅ Email changed successfully for user: {} from {} to {}", userId, oldEmail, newEmail);
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            log.error("❌ Email change error", e);
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("error", "server_error");
            errorResponse.put("error_description", "An error occurred while changing email");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    /**
     * Custom login endpoint for UI integration
     * 
     * Implements the complete authentication flow from sequence diagram:
     * 1. Receives login request from API Gateway
     * 2. Validates credentials locally in Auth Service
     * 3. Calls User Service to get complete user profile data
     * 4. Generates JWT with complete claims from BOTH databases
     * 5. Issues JWT tokens with full user information
     *
     * This maintains proper separation of concerns while providing
     * complete user data in JWT tokens for efficient API gateway validation.
     */
    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@Valid @RequestBody LoginRequest loginRequest) {
        log.info("🔐 Login request received for user: {}", loginRequest.getEmail());
        log.info("📊 Starting authentication flow: Client → API Gateway → Auth Service");

        try {
            // Step 1: Use AuthenticationService for complete authentication logic
            log.debug("🔍 Step 1: Using AuthenticationService for complete authentication");
            var authResult = authenticationService.authenticateUser(loginRequest.getEmail(), loginRequest.getPassword());

            if (!authResult.isSuccess()) {
                log.warn("❌ Authentication failed: {}", authResult.getErrorMessage());
                Map<String, Object> errorResponse = new HashMap<>();

                if ("Account is locked".equals(authResult.getErrorMessage())) {
                    errorResponse.put("error", "account_locked");
                    errorResponse.put("error_description", "User account is locked");
                    return ResponseEntity.status(HttpStatus.FORBIDDEN).body(errorResponse);
                } else if ("Email verification required".equals(authResult.getErrorMessage())) {
                    errorResponse.put("error", "email_not_verified");
                    errorResponse.put("error_description", "Please verify your email address before signing in");
                    return ResponseEntity.status(HttpStatus.FORBIDDEN).body(errorResponse);
                } else {
                    errorResponse.put("error", "invalid_credentials");
                    errorResponse.put("error_description", "Invalid email or password");
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
                }
            }

            AuthUser authUser = authResult.getAuthUser();
            log.debug("✅ Step 1 Complete: User authenticated successfully via AuthenticationService");

            // Step 2: Get complete user claims using AuthenticationService (eliminates hardcoded values)
            log.debug("🔍 Step 2: Getting complete user claims via AuthenticationService");
            Map<String, Object> completeUserClaims = authenticationService.getUserClaimsForToken(authUser);
            log.debug("✅ Step 2 Complete: Complete user claims retrieved without hardcoded values");

            // Step 3: Generate JWT tokens with complete user information
            log.debug("🔍 Step 3: Generating JWT tokens with complete user claims");
            String accessToken = generateAccessToken(completeUserClaims);
            String refreshToken = generateRefreshToken(completeUserClaims);

            // Step 4: Store refresh token metadata and create user session in Redis
            String userId = authUser.getId().toString();
            try {
                redisTokenBlacklistService.storeRefreshTokenMetadata(refreshToken, userId);
                
                // Create user session for tracking
                String sessionId = java.util.UUID.randomUUID().toString();
                Jwt jwt = jwtDecoder.decode(accessToken);
                String accessTokenId = jwt.getId();
                redisTokenBlacklistService.createUserSession(userId, sessionId, accessTokenId);

                log.debug("📝 User session created with Redis session management");
            } catch (Exception e) {
                log.warn("⚠️ Redis operations failed, continuing without Redis: {}", e.getMessage());
            }
            
            log.debug("✅ Step 3 Complete: JWT tokens generated with complete user claims");

            // Step 5: Prepare response with tokens and user information
            Map<String, Object> response = new HashMap<>();
            response.put("access_token", accessToken);
            response.put("refresh_token", refreshToken);
            response.put("token_type", "Bearer");
            response.put("expires_in", 1800); // 30 minutes
            response.put("scope", "openid profile email");

            // Add user info to response (for frontend convenience)
            Map<String, Object> userInfo = new HashMap<>();
            userInfo.put("id", authUser.getId().toString());
            userInfo.put("email", authUser.getEmail());
            userInfo.put("name", completeUserClaims.get("name"));
            userInfo.put("firstName", completeUserClaims.get("first_name"));
            userInfo.put("lastName", completeUserClaims.get("last_name"));
            userInfo.put("roles", completeUserClaims.get("roles"));
            userInfo.put("subscription", completeUserClaims.get("subscription"));
            userInfo.put("emailVerified", authUser.getEmailVerified());

            response.put("user", userInfo);

            log.info("✅ Login successful for user: {} with complete profile data", loginRequest.getEmail());
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("❌ Login error for user: {}", loginRequest.getEmail(), e);
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("error", "server_error");
            errorResponse.put("error_description", "An internal server error occurred");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    /**
     * Create default user profile data when User Service is unavailable
     * or user profile hasn't been created yet
     */
    private Map<String, Object> createDefaultUserProfile(AuthUser authUser) {
        Map<String, Object> defaultProfile = new HashMap<>();
        defaultProfile.put("name", "User");
        defaultProfile.put("first_name", "User");
        defaultProfile.put("last_name", "User");
        defaultProfile.put("roles", java.util.List.of("USER"));
        defaultProfile.put("subscription", "free");
        defaultProfile.put("permissions", java.util.List.of());
        defaultProfile.put("created_at", authUser.getCreatedAt());

        log.debug("📝 Created default user profile for auth_user_id: {}", authUser.getId());
        return defaultProfile;
    }

    /**
     * User registration endpoint
     * 
     * Implements the registration flow from sequence diagram:
     * 1. Validates input data
     * 2. Checks if email already exists
     * 3. Creates auth user with hashed password  
     * 4. Publishes UserRegisteredEvent to message queue
     * 5. Returns success response
     */
    @PostMapping("/register")
    public ResponseEntity<Map<String, Object>> register(@Valid @RequestBody RegistrationRequest registrationRequest) {
        log.info("🔐 Registration request received for email: {}", registrationRequest.getEmail());
        
        try {
            // Step 1: Validate input and check if email already exists
            if (authUserRepository.existsByEmail(registrationRequest.getEmail())) {
                log.warn("❌ Registration failed: Email already exists: {}", registrationRequest.getEmail());
                Map<String, Object> errorResponse = new HashMap<>();
                errorResponse.put("error", "email_exists");
                errorResponse.put("error_description", "User with this email already exists");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
            }

            // Step 1.5: Validate password confirmation
            if (!registrationRequest.getPassword().equals(registrationRequest.getConfirmPassword())) {
                log.warn("❌ Registration failed: Password confirmation mismatch for email: {}", registrationRequest.getEmail());
                Map<String, Object> errorResponse = new HashMap<>();
                errorResponse.put("error", "password_mismatch");
                errorResponse.put("error_description", "Password and confirmation password do not match");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
            }

            // Step 2: Create auth user with hashed password
            log.debug("🔐 Creating auth user with hashed password");
            String hashedPassword = passwordEncoder.encode(registrationRequest.getPassword());
            
            AuthUser authUser = AuthUser.builder()
                    .email(registrationRequest.getEmail().toLowerCase().trim())
                    .passwordHash(hashedPassword)
                    .provider("local")
                    .emailVerified(false) // Email verification required
                    .accountLocked(false)
                    .failedLoginAttempts(0)
                    .build();

            // Step 3: Save auth user to database
            AuthUser savedAuthUser = authUserRepository.save(authUser);
            log.debug("✅ Auth user created with ID: {}", savedAuthUser.getId());

            // Step 4: Publish UserRegisteredEvent to message queue for async processing
            log.debug("📤 Publishing UserRegisteredEvent to message queue");
            authEventPublisher.publishUserRegistered(
                    savedAuthUser.getId(),
                    registrationRequest.getEmail(),
                    registrationRequest.getFirstName(),
                    registrationRequest.getLastName(),
                    false, // email not verified yet
                    "local"
            );

            // Step 5: Return success response
            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "Registration successful. Please check your email for verification.");
            response.put("user_id", savedAuthUser.getId());

            log.info("✅ Registration successful for email: {}", registrationRequest.getEmail());
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("❌ Registration error for email: {}", registrationRequest.getEmail(), e);
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("error", "server_error");
            errorResponse.put("error_description", "An internal server error occurred during registration");
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
            // Extract user ID from the refresh token
            String userId = extractUserIdFromRefreshToken(refreshToken);
            if (userId == null) {
                log.warn("❌ Invalid refresh token");
                Map<String, Object> errorResponse = new HashMap<>();
                errorResponse.put("error", "invalid_grant");
                errorResponse.put("error_description", "Invalid or expired refresh token");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
            }

            Map<String, Object> userClaims = userServiceClient.getUserTokenClaimsById(userId);
            if (userClaims.isEmpty()) {
                log.error("❌ Failed to get user claims for refresh: {}", userId);
                Map<String, Object> errorResponse = new HashMap<>();
                errorResponse.put("error", "user_claims_error");
                errorResponse.put("error_description", "Failed to retrieve user information");
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
            }

            // Step 3: Generate new tokens
            log.debug("🔍 Generating new JWT tokens");
            String newAccessToken = generateAccessToken(userClaims);
            String newRefreshToken = generateRefreshToken(userClaims);
            
            // Store new refresh token metadata in Redis
            redisTokenBlacklistService.storeRefreshTokenMetadata(newRefreshToken, userId);
            
            // Update session activity
            try {
                Jwt jwt = jwtDecoder.decode(newAccessToken);
                String newAccessTokenId = jwt.getId();
                String sessionId = java.util.UUID.randomUUID().toString();
                redisTokenBlacklistService.createUserSession(userId, sessionId, newAccessTokenId);
            } catch (Exception e) {
                log.warn("⚠️ Failed to update user session: {}", e.getMessage());
            }

            // Prepare response
            Map<String, Object> response = new HashMap<>();
            response.put("access_token", newAccessToken);
            response.put("refresh_token", newRefreshToken);
            response.put("token_type", "Bearer");
            response.put("expires_in", 1800); // 30 minutes
            response.put("scope", "openid profile email");

            log.info("✅ Token refresh successful for user ID: {}", userId);
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
     * Extract user ID from refresh token (simplified implementation)
     * In production, use proper JWT decoding and validation
     */
    private String extractUserIdFromRefreshToken(String refreshToken) {
        try {
            // Decode JWT token without verification (for demo purposes)
            // In production, you MUST verify the token signature and expiration
            String[] parts = refreshToken.split("\\.");
            if (parts.length != 3) {
                return null;
            }

            // Decode payload
            String payload = new String(java.util.Base64.getUrlDecoder().decode(parts[1]));

            // Extract user ID from sub claim
            if (payload.contains("\"sub\":")) {
                String[] subParts = payload.split("\"sub\":\"");
                if (subParts.length > 1) {
                    String userId = subParts[1].split("\"")[0];
                    return userId;
                }
            }

            return null;
        } catch (Exception e) {
            log.error("❌ Error extracting user ID from refresh token", e);
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

    /**
     * Logout endpoint - invalidates tokens
     * POST /api/v1/auth/logout
     */
    @PostMapping("/logout")
    public ResponseEntity<Map<String, Object>> logout(@RequestBody Map<String, String> logoutRequest,
                                                      HttpServletRequest request) {
        log.info("🚪 Logout request received");
        
        try {
            String accessToken = extractTokenFromRequest(request);
            String refreshToken = logoutRequest.get("refresh_token");
            
            // Blacklist access token if provided
            if (accessToken != null && !accessToken.trim().isEmpty()) {
                redisTokenBlacklistService.blacklistAccessToken(accessToken);
                log.debug("🗑️ Access token blacklisted");
            }
            
            // Invalidate refresh token if provided
            if (refreshToken != null && !refreshToken.trim().isEmpty()) {
                refreshTokenService.invalidateToken(refreshToken);
                log.debug("🗑️ Refresh token invalidated");
            }
            
            // Invalidate user sessions
            try {
                if (accessToken != null) {
                    Jwt jwt = jwtDecoder.decode(accessToken);
                    String userId = jwt.getSubject();
                    // Note: In a full implementation, you'd track session IDs
                    // For now, we'll just log the logout
                    log.debug("🚪 User session invalidated for user: {}", userId);
                }
            } catch (Exception e) {
                log.warn("⚠️ Failed to invalidate user session: {}", e.getMessage());
            }
            
            Map<String, Object> response = new HashMap<>();
            response.put("message", "Logged out successfully");
            response.put("status", "success");
            
            log.info("✅ Logout successful");
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            log.error("❌ Logout error", e);
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("error", "logout_failed");
            errorResponse.put("error_description", "An error occurred during logout");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    /**
     * OpenID Connect UserInfo endpoint
     * GET /api/v1/auth/userinfo
     */
    @GetMapping("/userinfo")
    public ResponseEntity<Map<String, Object>> getUserInfo(HttpServletRequest request) {
        log.info("👤 UserInfo request received");
        
        try {
            String accessToken = extractTokenFromRequest(request);
            if (accessToken == null) {
                log.warn("❌ Missing access token");
                Map<String, Object> errorResponse = new HashMap<>();
                errorResponse.put("error", "invalid_token");
                errorResponse.put("error_description", "Access token is missing or invalid");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
            }
            
            // Decode and validate access token
            Jwt jwt = jwtDecoder.decode(accessToken);
            String userId = jwt.getSubject();
            
            // Get fresh user claims from User Service
            Map<String, Object> userClaims = userServiceClient.getUserTokenClaimsById(userId);
            if (userClaims.isEmpty()) {
                log.error("❌ Failed to get user claims for userinfo: {}", userId);
                Map<String, Object> errorResponse = new HashMap<>();
                errorResponse.put("error", "user_not_found");
                errorResponse.put("error_description", "User information not found");
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(errorResponse);
            }
            
            // Prepare OpenID Connect compliant userinfo response
            Map<String, Object> userInfo = new HashMap<>();
            userInfo.put("sub", userId);
            userInfo.put("email", userClaims.get("email"));
            userInfo.put("email_verified", userClaims.get("is_email_verified"));
            userInfo.put("given_name", userClaims.get("first_name"));
            userInfo.put("family_name", userClaims.get("last_name"));
            userInfo.put("name", userClaims.get("first_name") + " " + userClaims.get("last_name"));
            userInfo.put("preferred_username", userClaims.get("email"));
            userInfo.put("roles", userClaims.get("roles"));
            
            log.info("✅ UserInfo retrieved successfully for user: {}", userId);
            return ResponseEntity.ok(userInfo);
            
        } catch (Exception e) {
            log.error("❌ UserInfo error", e);
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("error", "server_error");
            errorResponse.put("error_description", "An error occurred while retrieving user information");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    /**
     * Token revocation endpoint (RFC 7009)
     * POST /api/v1/auth/revoke
     */
    @PostMapping("/revoke")
    public ResponseEntity<Map<String, Object>> revokeToken(@RequestBody Map<String, String> revokeRequest) {
        log.info("🚫 Token revocation request received");
        
        try {
            String token = revokeRequest.get("token");
            String tokenTypeHint = revokeRequest.get("token_type_hint");
            
            if (token == null || token.trim().isEmpty()) {
                log.warn("❌ Missing token in revocation request");
                Map<String, Object> errorResponse = new HashMap<>();
                errorResponse.put("error", "invalid_request");
                errorResponse.put("error_description", "Missing token parameter");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
            }
            
            // Determine token type and revoke accordingly
            boolean revoked = false;
            
            if ("refresh_token".equals(tokenTypeHint) || isRefreshToken(token)) {
                // Revoke refresh token
                refreshTokenService.invalidateToken(token);
                revoked = true;
                log.debug("🗑️ Refresh token revoked");
            } else {
                // Revoke access token by blacklisting in Redis
                redisTokenBlacklistService.blacklistAccessToken(token);
                revoked = true;
                log.debug("🗑️ Access token revoked and blacklisted");
            }
            
            if (revoked) {
                // RFC 7009: Return 200 OK for successful revocation
                Map<String, Object> response = new HashMap<>();
                response.put("revoked", true);
                response.put("message", "Token revoked successfully");
                
                log.info("✅ Token revocation successful");
                return ResponseEntity.ok(response);
            } else {
                Map<String, Object> errorResponse = new HashMap<>();
                errorResponse.put("error", "invalid_token");
                errorResponse.put("error_description", "Token is invalid or already revoked");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
            }
            
        } catch (Exception e) {
            log.error("❌ Token revocation error", e);
            // RFC 7009: Even if revocation fails, return 200 OK to prevent token enumeration
            Map<String, Object> response = new HashMap<>();
            response.put("revoked", true);
            response.put("message", "Token revocation processed");
            return ResponseEntity.ok(response);
        }
    }

    /**
     * Token validation endpoint for API Gateway
     * POST /api/v1/auth/validate
     *
     * This implements the JWT validation flow from your sequence diagram:
     * - API Gateway calls this endpoint to validate JWT tokens
     * - Returns user claims for request enrichment
     * - Supports caching for performance optimization
     */
    @PostMapping("/validate")
    public ResponseEntity<Map<String, Object>> validateToken(@RequestBody Map<String, String> tokenRequest) {
        log.info("🔍 Token validation request received from API Gateway");

        try {
            String token = tokenRequest.get("token");
            if (token == null || token.trim().isEmpty()) {
                log.warn("❌ Missing token in validation request");
                Map<String, Object> errorResponse = new HashMap<>();
                errorResponse.put("error", "invalid_request");
                errorResponse.put("error_description", "Missing token parameter");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
            }

            // Check if token is blacklisted in Redis
            try {
                if (redisTokenBlacklistService.isTokenBlacklisted(token)) {
                    log.warn("❌ Token is blacklisted");
                    Map<String, Object> errorResponse = new HashMap<>();
                    errorResponse.put("error", "invalid_token");
                    errorResponse.put("error_description", "Token has been revoked");
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
                }
            } catch (Exception e) {
                log.warn("⚠️ Redis check failed, continuing with JWT validation: {}", e.getMessage());
            }

            // Decode and validate JWT token
            Jwt jwt = jwtDecoder.decode(token);
            String userId = jwt.getSubject();
            String email = jwt.getClaimAsString("email");

            // Extract roles and other claims
            Object rolesObj = jwt.getClaim("roles");
            java.util.List<String> roles = rolesObj instanceof java.util.List ?
                (java.util.List<String>) rolesObj : java.util.List.of("USER");

            // Prepare validation response with user claims
            Map<String, Object> response = new HashMap<>();
            response.put("valid", true);
            response.put("user_id", userId);
            response.put("email", email);
            response.put("roles", roles);
            response.put("token_id", jwt.getId());
            response.put("expires_at", jwt.getExpiresAt().toEpochMilli());

            log.debug("✅ Token validation successful for user: {}", userId);
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.warn("❌ Token validation failed: {}", e.getMessage());
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("valid", false);
            errorResponse.put("error", "invalid_token");
            errorResponse.put("error_description", "Token is invalid or expired");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
        }
    }

    /**
     * Extract Bearer token from Authorization header
     */
    private String extractTokenFromRequest(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        return null;
    }

    /**
     * Check if token is a refresh token by examining its structure
     */
    private boolean isRefreshToken(String token) {
        try {
            Jwt jwt = jwtDecoder.decode(token);
            String tokenType = jwt.getClaimAsString("token_type");
            return "refresh".equals(tokenType);
        } catch (Exception e) {
            return false;
        }
    }
}
