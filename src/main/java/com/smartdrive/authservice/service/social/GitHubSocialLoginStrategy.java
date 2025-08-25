package com.smartdrive.authservice.service.social;

import com.smartdrive.authservice.dto.SocialUserInfo;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * GitHub Social Login Strategy
 * TODO: Implement when GitHub login is needed
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class GitHubSocialLoginStrategy implements SocialLoginStrategy {

    @Override
    public String getProviderName() {
        return "github";
    }

    @Override
    public SocialUserInfo exchangeCodeForUserInfo(String authorizationCode, String redirectUri) {
        // TODO: Implement GitHub OAuth2 flow
        throw new UnsupportedOperationException("GitHub social login not implemented yet");
    }

    @Override
    public String getAuthorizationUrl(String state, String redirectUri) {
        // TODO: Implement GitHub authorization URL
        throw new UnsupportedOperationException("GitHub social login not implemented yet");
    }

    @Override
    public boolean supports(String provider) {
        return "github".equalsIgnoreCase(provider);
    }
}
