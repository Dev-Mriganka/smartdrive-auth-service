package com.smartdrive.authservice.service;

import java.util.UUID;

import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.smartdrive.authservice.config.SQSConfig;
import com.smartdrive.authservice.config.SQSConfig.QueueNames;
import com.smartdrive.authservice.dto.events.EmailChangedEvent;
import com.smartdrive.authservice.dto.events.EmailVerifiedEvent;
import com.smartdrive.authservice.dto.events.UserRegisteredEvent;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import software.amazon.awssdk.services.sqs.SqsClient;
import software.amazon.awssdk.services.sqs.model.SendMessageRequest;
import software.amazon.awssdk.services.sqs.model.SendMessageResponse;

/**
 * Service for publishing events to SQS queues
 * Handles user registration, email verification, and email change events
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AuthEventPublisher {

    private final SqsClient sqsClient;
    private final ObjectMapper objectMapper;
    private final QueueNames queueNames;

    /**
     * Publish user registration event
     */
    public void publishUserRegistered(UUID userId, String email, String firstName, String lastName,
            Boolean emailVerified, String provider) {
        try {
            UserRegisteredEvent event = UserRegisteredEvent.of(userId, email, firstName, lastName,
                    emailVerified, provider);

            String messageBody = objectMapper.writeValueAsString(event);

            SendMessageRequest request = SendMessageRequest.builder()
                    .queueUrl(getQueueUrl(SQSConfig.QueueNames.USER_REGISTERED_QUEUE))
                    .messageBody(messageBody)
                    .build();

            SendMessageResponse response = sqsClient.sendMessage(request);

            log.info("✅ Published UserRegisteredEvent for user: {} with message ID: {}",
                    userId, response.messageId());

        } catch (Exception e) {
            log.error("❌ Failed to publish UserRegisteredEvent for user: {}", userId, e);
            throw new RuntimeException("Failed to publish user registration event", e);
        }
    }

    /**
     * Publish email verification event
     */
    public void publishEmailVerified(UUID userId, String email) {
        try {
            EmailVerifiedEvent event = EmailVerifiedEvent.of(userId, email);

            String messageBody = objectMapper.writeValueAsString(event);

            SendMessageRequest request = SendMessageRequest.builder()
                    .queueUrl(getQueueUrl(SQSConfig.QueueNames.EMAIL_VERIFIED_QUEUE))
                    .messageBody(messageBody)
                    .build();

            SendMessageResponse response = sqsClient.sendMessage(request);

            log.info("✅ Published EmailVerifiedEvent for user: {} with message ID: {}",
                    userId, response.messageId());

        } catch (Exception e) {
            log.error("❌ Failed to publish EmailVerifiedEvent for user: {}", userId, e);
            throw new RuntimeException("Failed to publish email verification event", e);
        }
    }

    /**
     * Publish email change event
     */
    public void publishEmailChanged(UUID userId, String oldEmail, String newEmail, Boolean emailVerified) {
        try {
            EmailChangedEvent event = EmailChangedEvent.of(userId, oldEmail, newEmail, emailVerified);

            String messageBody = objectMapper.writeValueAsString(event);

            SendMessageRequest request = SendMessageRequest.builder()
                    .queueUrl(getQueueUrl(SQSConfig.QueueNames.EMAIL_CHANGED_QUEUE))
                    .messageBody(messageBody)
                    .build();

            SendMessageResponse response = sqsClient.sendMessage(request);

            log.info("✅ Published EmailChangedEvent for user: {} from {} to {} with message ID: {}",
                    userId, oldEmail, newEmail, response.messageId());

        } catch (Exception e) {
            log.error("❌ Failed to publish EmailChangedEvent for user: {}", userId, e);
            throw new RuntimeException("Failed to publish email change event", e);
        }
    }

    /**
     * Get queue URL for a given queue name
     */
    private String getQueueUrl(String queueName) {
        try {
            return sqsClient.getQueueUrl(builder -> builder.queueName(queueName)).queueUrl();
        } catch (Exception e) {
            log.error("❌ Failed to get queue URL for queue: {}", queueName, e);
            throw new RuntimeException("Failed to get queue URL for: " + queueName, e);
        }
    }
}
