package com.smartdrive.authservice.service;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import com.smartdrive.authservice.client.UserServiceClient;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Service for handling social authentication flows
 * Currently supports Google OAuth2 login
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class SocialAuthService {

    private final ClientRegistrationRepository clientRegistrationRepository;
    private final UserServiceClient userServiceClient;
    private final JwtEncoder jwtEncoder;
    private final WebClient.Builder webClientBuilder;

    @Value("${spring.security.oauth2.client.registration.google.client-id}")
    private String googleClientId;

    @Value("${spring.security.oauth2.client.registration.google.client-secret}")
    private String googleClientSecret;

    /**
     * Generate Google OAuth2 authorization URL
     */
    public String getGoogleAuthorizationUrl(String redirectUri) {
        log.info("🔗 Generating Google OAuth2 authorization URL");

        try {
            ClientRegistration googleRegistration = clientRegistrationRepository.findByRegistrationId("google");

            if (googleRegistration == null) {
                throw new RuntimeException("Google OAuth2 client registration not found");
            }

            String state = "smartdrive_" + UUID.randomUUID().toString();
            String nonce = UUID.randomUUID().toString();

            // Build authorization URL manually for better control
            String authorizationUri = googleRegistration.getProviderDetails()
                    .getAuthorizationUri();

            String authUrl = String.format(
                    "%s?client_id=%s&redirect_uri=%s&scope=%s&response_type=code&state=%s&nonce=%s",
                    authorizationUri,
                    URLEncoder.encode(googleClientId, StandardCharsets.UTF_8),
                    URLEncoder.encode(redirectUri, StandardCharsets.UTF_8),
                    URLEncoder.encode("openid profile email", StandardCharsets.UTF_8),
                    URLEncoder.encode(state, StandardCharsets.UTF_8),
                    URLEncoder.encode(nonce, StandardCharsets.UTF_8));
            log.info("✅ Google OAuth2 authorization URL generated: {}", authUrl);
            return authUrl;

        } catch (Exception e) {
            log.error("❌ Failed to generate Google OAuth2 authorization URL", e);
            throw new RuntimeException("Failed to generate Google authorization URL", e);
        }
    }

    /**
     * Process Google OAuth2 callback and exchange code for tokens
     */
    public Map<String, Object> processGoogleCallback(String authorizationCode) {
        return processGoogleCallback(authorizationCode, "http://localhost:8080/api/v1/auth/social/google/callback");
    }

    /**
     * Process Google OAuth2 callback and exchange code for tokens with custom
     * redirect URI
     */
    public Map<String, Object> processGoogleCallback(String authorizationCode, String redirectUri) {
        log.info("🔄 Processing Google OAuth2 callback with redirect_uri: {}", redirectUri);

        try {
            // Step 1: Exchange authorization code for access token
            Map<String, Object> googleTokens = exchangeCodeForTokens(authorizationCode, redirectUri);
            String googleAccessToken = (String) googleTokens.get("access_token");

            // Step 2: Get user profile from Google
            Map<String, Object> googleUserProfile = getGoogleUserProfile(googleAccessToken);

            // Step 3: Create or find user in our system
            Map<String, Object> userClaims = createOrUpdateUserFromGoogleProfile(googleUserProfile);

            // Step 4: Generate our JWT tokens
            String accessToken = generateAccessToken(userClaims);
            String refreshToken = generateRefreshToken(userClaims);

            // Step 5: Prepare response
            Map<String, Object> response = new HashMap<>();
            response.put("access_token", accessToken);
            response.put("refresh_token", refreshToken);
            response.put("token_type", "Bearer");
            response.put("expires_in", 1800); // 30 minutes
            response.put("scope", "openid profile email");

            // Add user info
            Map<String, Object> userInfo = new HashMap<>();
            userInfo.put("id", userClaims.get("user_id").toString());
            userInfo.put("username", userClaims.get("username"));
            userInfo.put("email", userClaims.get("email"));
            userInfo.put("firstName", userClaims.get("first_name"));
            userInfo.put("lastName", userClaims.get("last_name"));
            userInfo.put("roles", userClaims.get("roles"));
            userInfo.put("loginMethod", "google");

            response.put("user", userInfo);

            log.info("✅ Google OAuth2 authentication successful for: {}", userClaims.get("email"));
            return response;

        } catch (Exception e) {
            log.error("❌ Google OAuth2 callback processing failed", e);
            throw new RuntimeException("Failed to process Google OAuth2 callback", e);
        }
    }

    /**
     * Exchange authorization code for Google access token
     */
    private Map<String, Object> exchangeCodeForTokens(String authorizationCode, String redirectUri) {
        log.debug("🔄 Exchanging authorization code for Google access token with redirect_uri: {}", redirectUri);

        try {
            WebClient webClient = webClientBuilder.build();

            Map<String, Object> tokenRequest = Map.of(
                    "client_id", googleClientId,
                    "client_secret", googleClientSecret,
                    "code", authorizationCode,
                    "grant_type", "authorization_code",
                    "redirect_uri", redirectUri);
            Map<String, Object> tokenResponse = webClient.post()
                    .uri("https://oauth2.googleapis.com/token")
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .bodyValue(buildFormData(tokenRequest))
                    .retrieve()
                    .bodyToMono(Map.class)
                    .block();

            if (tokenResponse == null || !tokenResponse.containsKey("access_token")) {
                throw new RuntimeException("Failed to get access token from Google");
            }

            log.debug("✅ Successfully exchanged code for Google access token");
            return tokenResponse;

        } catch (Exception e) {
            log.error("❌ Failed to exchange authorization code for Google tokens", e);
            throw new RuntimeException("Token exchange failed", e);
        }
    }

    /**
     * Get user profile from Google using access token
     */
    private Map<String, Object> getGoogleUserProfile(String accessToken) {
        log.debug("🔄 Fetching user profile from Google");

        try {
            WebClient webClient = webClientBuilder.build();

            Map<String, Object> userProfile = webClient.get()
                    .uri("https://www.googleapis.com/oauth2/v2/userinfo")
                    .header("Authorization", "Bearer " + accessToken)
                    .retrieve()
                    .bodyToMono(Map.class)
                    .block();

            if (userProfile == null) {
                throw new RuntimeException("Failed to get user profile from Google");
            }

            log.debug("✅ Successfully fetched Google user profile for: {}", userProfile.get("email"));
            return userProfile;

        } catch (Exception e) {
            log.error("❌ Failed to fetch Google user profile", e);
            throw new RuntimeException("Failed to fetch user profile", e);
        }
    }

    /**
     * Create or update user from Google profile
     * Handles both new users and existing users logging in with Google
     */
    private Map<String, Object> createOrUpdateUserFromGoogleProfile(Map<String, Object> googleProfile) {
        String email = (String) googleProfile.get("email");
        String firstName = (String) googleProfile.get("given_name");
        String lastName = (String) googleProfile.get("family_name");
        String googleId = (String) googleProfile.get("id");
        String picture = (String) googleProfile.get("picture");

        log.info("🔄 Processing Google login for email: {}", email);

        try {
            // Check if user exists by email
            Map<String, Object> existingUser = userServiceClient.getUserByEmail(email);

            if (existingUser != null && !existingUser.isEmpty()) {
                log.info("✅ Found existing user for Google login: {}", email);
                
                // Update existing user with Google information if not already linked
                String currentGoogleId = (String) existingUser.get("googleId");
                if (currentGoogleId == null || currentGoogleId.isEmpty()) {
                    log.info("🔗 Linking existing user {} to Google account", email);
                    
                    // Update user with Google ID and profile picture
                    Map<String, Object> updateData = Map.of(
                            "googleId", googleId,
                            "profilePictureUrl", picture != null ? picture : existingUser.get("profilePictureUrl"),
                            "isEmailVerified", true, // Google emails are verified
                            "firstName", firstName != null ? firstName : existingUser.get("firstName"),
                            "lastName", lastName != null ? lastName : existingUser.get("lastName")
                    );
                    
                    try {
                        Map<String, Object> updatedUser = userServiceClient.linkGoogleAccount(email, updateData);
                        log.info("✅ Successfully linked existing user to Google account: {}", email);
                        return updatedUser;
                    } catch (Exception linkError) {
                        log.warn("⚠️ Failed to link Google account, using existing user data: {}", linkError.getMessage());
                        return existingUser;
                    }
                } else {
                    log.info("🔗 User {} already linked to Google account", email);
                    return existingUser;
                }
            }

            // Create new user from Google profile (no existing user found)
            log.info("👤 Creating new user from Google profile: {}", email);
            Map<String, Object> newUserData = Map.of(
                    "email", email,
                    "firstName", firstName != null ? firstName : "Google",
                    "lastName", lastName != null ? lastName : "User",
                    "googleId", googleId,
                    "profilePictureUrl", picture != null ? picture : "",
                    "isEmailVerified", true // Google emails are pre-verified
            );

            Map<String, Object> createdUser = userServiceClient.createGoogleUser(newUserData);

            log.info("✅ Created new user from Google profile: {}", email);
            return createdUser;

        } catch (Exception e) {
            log.error("❌ Failed to process Google user: {}", email, e);
            throw new RuntimeException("Failed to process Google user", e);
        }
    }



    /**
     * Generate JWT access token for Google authenticated user
     */
    private String generateAccessToken(Map<String, Object> userClaims) {
        Instant now = Instant.now();
        Instant expiry = now.plusSeconds(1800); // 30 minutes

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("smartdrive-auth-service")
                .subject(userClaims.get("user_id").toString())
                .audience(java.util.List.of("smartdrive-web"))
                .issuedAt(now)
                .expiresAt(expiry)
                .notBefore(now)
                .id(UUID.randomUUID().toString())
                .claim("email", userClaims.get("email"))
                .claim("roles", userClaims.get("roles"))
                .claim("loginMethod", "google")
                .build();

        return jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }

    /**
     * Generate JWT refresh token for Google authenticated user
     */
    private String generateRefreshToken(Map<String, Object> userClaims) {
        Instant now = Instant.now();
        Instant expiry = now.plusSeconds(604800); // 7 days

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("smartdrive-auth-service")
                .subject(userClaims.get("user_id").toString())
                .audience(java.util.List.of("smartdrive-web"))
                .issuedAt(now)
                .expiresAt(expiry)
                .notBefore(now)
                .id(UUID.randomUUID().toString())
                .claim("token_type", "refresh")
                .build();

        return jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }

    /**
     * Build form data for HTTP requests
     */
    private String buildFormData(Map<String, Object> data) {
        return data.entrySet().stream()
                .map(entry -> URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8) +
                        "=" +
                        URLEncoder.encode(entry.getValue().toString(), StandardCharsets.UTF_8))
                .reduce((a, b) -> a + "&" + b)
                .orElse("");
    }
}
