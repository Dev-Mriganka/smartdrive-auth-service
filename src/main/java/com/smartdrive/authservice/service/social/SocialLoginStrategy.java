package com.smartdrive.authservice.service.social;

import com.smartdrive.authservice.dto.SocialUserInfo;

/**
 * Strategy interface for social login providers
 */
public interface SocialLoginStrategy {
    
    /**
     * Get the provider name (e.g., "google", "github")
     */
    String getProviderName();
    
    /**
     * Exchange authorization code for user info
     */
    SocialUserInfo exchangeCodeForUserInfo(String authorizationCode, String redirectUri);
    
    /**
     * Get the authorization URL for this provider
     */
    String getAuthorizationUrl(String state, String redirectUri);
    
    /**
     * Validate if this strategy supports the given provider
     */
    boolean supports(String provider);
}
