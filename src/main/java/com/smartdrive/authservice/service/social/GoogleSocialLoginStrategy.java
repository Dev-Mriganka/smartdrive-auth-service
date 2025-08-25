package com.smartdrive.authservice.service.social;

import com.smartdrive.authservice.dto.SocialUserInfo;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class GoogleSocialLoginStrategy implements SocialLoginStrategy {

    private final RestTemplate restTemplate;
    
    @Value("${spring.security.oauth2.client.registration.google.client-id}")
    private String clientId;
    
    @Value("${spring.security.oauth2.client.registration.google.client-secret}")
    private String clientSecret;
    
    @Value("${spring.security.oauth2.client.registration.google.redirect-uri}")
    private String redirectUri;

    @Override
    public String getProviderName() {
        return "google";
    }

    @Override
    public SocialUserInfo exchangeCodeForUserInfo(String authorizationCode, String redirectUri) {
        log.info("🔄 Exchanging Google authorization code for user info");
        
        try {
            // Step 1: Exchange authorization code for access token
            String tokenUrl = "https://oauth2.googleapis.com/token";
            
            HttpHeaders tokenHeaders = new HttpHeaders();
            tokenHeaders.set("Content-Type", "application/x-www-form-urlencoded");
            
            String tokenRequestBody = String.format(
                "grant_type=authorization_code&" +
                "client_id=%s&" +
                "client_secret=%s&" +
                "code=%s&" +
                "redirect_uri=%s",
                clientId, clientSecret, authorizationCode, redirectUri
            );
            
            HttpEntity<String> tokenRequest = new HttpEntity<>(tokenRequestBody, tokenHeaders);
            ResponseEntity<Map> tokenResponse = restTemplate.exchange(
                tokenUrl, HttpMethod.POST, tokenRequest, Map.class
            );
            
            if (!tokenResponse.getStatusCode().is2xxSuccessful() || tokenResponse.getBody() == null) {
                throw new RuntimeException("Failed to exchange authorization code for access token");
            }
            
            String accessToken = (String) tokenResponse.getBody().get("access_token");
            
            // Step 2: Get user info using access token
            String userInfoUrl = "https://www.googleapis.com/oauth2/v2/userinfo";
            
            HttpHeaders userInfoHeaders = new HttpHeaders();
            userInfoHeaders.set("Authorization", "Bearer " + accessToken);
            
            HttpEntity<Void> userInfoRequest = new HttpEntity<>(userInfoHeaders);
            ResponseEntity<Map> userInfoResponse = restTemplate.exchange(
                userInfoUrl, HttpMethod.GET, userInfoRequest, Map.class
            );
            
            if (!userInfoResponse.getStatusCode().is2xxSuccessful() || userInfoResponse.getBody() == null) {
                throw new RuntimeException("Failed to get user info from Google");
            }
            
            Map<String, Object> userInfo = userInfoResponse.getBody();
            
            // Step 3: Build SocialUserInfo
            SocialUserInfo socialUserInfo = SocialUserInfo.builder()
                    .providerId((String) userInfo.get("id"))
                    .providerName(getProviderName())
                    .email((String) userInfo.get("email"))
                    .firstName((String) userInfo.get("given_name"))
                    .lastName((String) userInfo.get("family_name"))
                    .displayName((String) userInfo.get("name"))
                    .profilePictureUrl((String) userInfo.get("picture"))
                    .locale((String) userInfo.get("locale"))
                    .emailVerified(Boolean.TRUE.equals(userInfo.get("verified_email")))
                    .build();
            
            log.info("✅ Successfully retrieved Google user info for: {}", socialUserInfo.getEmail());
            return socialUserInfo;
            
        } catch (Exception e) {
            log.error("❌ Error exchanging Google authorization code for user info", e);
            throw new RuntimeException("Failed to process Google social login", e);
        }
    }

    @Override
    public String getAuthorizationUrl(String state, String redirectUri) {
        String scope = "openid profile email";
        return String.format(
            "https://accounts.google.com/o/oauth2/v2/auth?" +
            "client_id=%s&" +
            "redirect_uri=%s&" +
            "response_type=code&" +
            "scope=%s&" +
            "state=%s",
            clientId, redirectUri, scope, state
        );
    }

    @Override
    public boolean supports(String provider) {
        return "google".equalsIgnoreCase(provider);
    }
}
