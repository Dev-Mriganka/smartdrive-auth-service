package com.smartdrive.authservice.dto.events;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Event published when a user is registered in Auth Service
 * Used for creating user profile in User Service
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserRegisteredEvent {

    private UUID userId; // auth_user_id
    private String email;
    private String firstName;
    private String lastName;
    private Boolean emailVerified;
    private String provider; // 'local', 'google', 'github'
    private LocalDateTime createdAt;
    private LocalDateTime eventTimestamp;

    // Helper method to set event timestamp
    public static UserRegisteredEvent of(UUID userId, String email, String firstName, String lastName, 
                                       Boolean emailVerified, String provider) {
        return UserRegisteredEvent.builder()
                .userId(userId)
                .email(email)
                .firstName(firstName)
                .lastName(lastName)
                .emailVerified(emailVerified)
                .provider(provider)
                .createdAt(LocalDateTime.now())
                .eventTimestamp(LocalDateTime.now())
                .build();
    }
}
