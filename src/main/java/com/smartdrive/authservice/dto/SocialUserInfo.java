package com.smartdrive.authservice.dto;

import lombok.Builder;
import lombok.Data;

/**
 * DTO for social login user information
 */
@Data
@Builder
public class SocialUserInfo {
    
    private String providerId;        // Unique ID from the social provider
    private String providerName;      // Provider name (google, github, etc.)
    private String email;
    private String firstName;
    private String lastName;
    private String displayName;
    private String profilePictureUrl;
    private String locale;
    private boolean emailVerified;
    
    // Additional provider-specific fields
    private String username;          // For GitHub
    private String company;           // For GitHub
    private String location;          // For GitHub
    private String bio;               // For GitHub
}
