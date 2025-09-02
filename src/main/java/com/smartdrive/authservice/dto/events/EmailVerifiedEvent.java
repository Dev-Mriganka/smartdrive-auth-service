package com.smartdrive.authservice.dto.events;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Event published when user email is verified in Auth Service
 * Used for updating email verification status in User Service
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class EmailVerifiedEvent {

    private UUID userId; // auth_user_id
    private String email;
    private LocalDateTime verifiedAt;
    private LocalDateTime eventTimestamp;

    // Helper method to set event timestamp
    public static EmailVerifiedEvent of(UUID userId, String email) {
        return EmailVerifiedEvent.builder()
                .userId(userId)
                .email(email)
                .verifiedAt(LocalDateTime.now())
                .eventTimestamp(LocalDateTime.now())
                .build();
    }
}
