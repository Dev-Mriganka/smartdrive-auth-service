package com.smartdrive.authservice.service;

import com.smartdrive.authservice.client.UserServiceClient;
import com.smartdrive.authservice.dto.SocialUserInfo;
import com.smartdrive.authservice.service.social.SocialLoginStrategy;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class SocialLoginService {

    private final List<SocialLoginStrategy> socialLoginStrategies;
    private final UserServiceClient userServiceClient;

    /**
     * Process social login for a specific provider
     */
    public Map<String, Object> processSocialLogin(String provider, String authorizationCode, String redirectUri) {
        log.info("🔄 Processing social login for provider: {}", provider);
        
        // Find the appropriate strategy
        SocialLoginStrategy strategy = findStrategy(provider);
        if (strategy == null) {
            throw new IllegalArgumentException("Unsupported social login provider: " + provider);
        }
        
        // Exchange authorization code for user info
        SocialUserInfo socialUserInfo = strategy.exchangeCodeForUserInfo(authorizationCode, redirectUri);
        
        // Check if user exists in our system
        Map<String, Object> existingUser = userServiceClient.findUserByEmail(socialUserInfo.getEmail());
        
        if (existingUser.isEmpty()) {
            // User doesn't exist, create new user
            log.info("👤 Creating new user from social login: {}", socialUserInfo.getEmail());
            Map<String, Object> newUser = createUserFromSocialLogin(socialUserInfo);
            return generateTokenResponse(newUser);
        } else {
            // User exists, link social account and return token
            log.info("👤 User exists, linking social account: {}", socialUserInfo.getEmail());
            Map<String, Object> linkedUser = linkSocialAccount(existingUser, socialUserInfo);
            return generateTokenResponse(linkedUser);
        }
    }

    /**
     * Get authorization URL for a specific provider
     */
    public String getAuthorizationUrl(String provider, String redirectUri) {
        log.info("🔗 Getting authorization URL for provider: {}", provider);
        
        SocialLoginStrategy strategy = findStrategy(provider);
        if (strategy == null) {
            throw new IllegalArgumentException("Unsupported social login provider: " + provider);
        }
        
        String state = UUID.randomUUID().toString();
        return strategy.getAuthorizationUrl(state, redirectUri);
    }

    /**
     * Find the appropriate strategy for the provider
     */
    private SocialLoginStrategy findStrategy(String provider) {
        return socialLoginStrategies.stream()
                .filter(strategy -> strategy.supports(provider))
                .findFirst()
                .orElse(null);
    }

    /**
     * Create a new user from social login
     */
    private Map<String, Object> createUserFromSocialLogin(SocialUserInfo socialUserInfo) {
        // Create user data for registration
        Map<String, Object> userData = Map.of(
            "username", generateUsername(socialUserInfo.getEmail()),
            "email", socialUserInfo.getEmail(),
            "firstName", socialUserInfo.getFirstName() != null ? socialUserInfo.getFirstName() : "",
            "lastName", socialUserInfo.getLastName() != null ? socialUserInfo.getLastName() : "",
            "profilePictureUrl", socialUserInfo.getProfilePictureUrl(),
            "providerId", socialUserInfo.getProviderId(),
            "providerName", socialUserInfo.getProviderName(),
            "isEmailVerified", socialUserInfo.isEmailVerified()
        );
        
        return userServiceClient.createUserFromSocialLogin(userData);
    }

    /**
     * Link social account to existing user
     */
    private Map<String, Object> linkSocialAccount(Map<String, Object> existingUser, SocialUserInfo socialUserInfo) {
        // Link social account data
        Map<String, Object> socialAccountData = Map.of(
            "userId", existingUser.get("id"),
            "providerId", socialUserInfo.getProviderId(),
            "providerName", socialUserInfo.getProviderName(),
            "email", socialUserInfo.getEmail(),
            "profilePictureUrl", socialUserInfo.getProfilePictureUrl()
        );
        
        return userServiceClient.linkSocialAccount(socialAccountData);
    }

    /**
     * Generate token response for authenticated user
     */
    private Map<String, Object> generateTokenResponse(Map<String, Object> user) {
        // This will be handled by the OAuth2 token endpoint
        // We return the user data for now
        return Map.of(
            "user", user,
            "message", "Social login successful"
        );
    }

    /**
     * Generate a unique username from email
     */
    private String generateUsername(String email) {
        String baseUsername = email.split("@")[0];
        String timestamp = String.valueOf(System.currentTimeMillis());
        return baseUsername + "_" + timestamp.substring(timestamp.length() - 4);
    }
}
