package com.smartdrive.authservice.dto.events;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Event published when user email is changed in Auth Service
 * Used for updating email in User Service and other dependent services
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class EmailChangedEvent {

    private UUID userId; // auth_user_id
    private String oldEmail;
    private String newEmail;
    private Boolean emailVerified; // Usually false after email change
    private LocalDateTime changedAt;
    private LocalDateTime eventTimestamp;

    // Helper method to set event timestamp
    public static EmailChangedEvent of(UUID userId, String oldEmail, String newEmail, Boolean emailVerified) {
        return EmailChangedEvent.builder()
                .userId(userId)
                .oldEmail(oldEmail)
                .newEmail(newEmail)
                .emailVerified(emailVerified)
                .changedAt(LocalDateTime.now())
                .eventTimestamp(LocalDateTime.now())
                .build();
    }
}
