package com.smartdrive.authservice.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sqs.SqsClient;

/**
 * AWS SQS Configuration for Auth Service
 * Handles event publishing to User Service and other services
 */
@Configuration
public class SQSConfig {

    @Value("${AWS_REGION:us-east-1}")
    private String region;

    @Value("${AWS_SQS_ENDPOINT:https://sqs.us-east-1.amazonaws.com}")
    private String sqsEndpoint;

    /**
     * SQS Client for AWS operations
     */
    @Bean
    public SqsClient sqsClient() {
        return SqsClient.builder()
                .region(Region.of(region))
                .credentialsProvider(DefaultCredentialsProvider.create())
                .endpointOverride(java.net.URI.create(sqsEndpoint))
                .build();
    }

    /**
     * Queue URLs for different events
     */
    public static class QueueUrls {
        public static final String USER_REGISTERED_QUEUE = "https://sqs.us-east-1.amazonaws.com/159014723710/smartdrive-user-registered-queue";
        public static final String EMAIL_VERIFIED_QUEUE = "https://sqs.us-east-1.amazonaws.com/159014723710/smartdrive-email-verified-queue";
        public static final String EMAIL_CHANGED_QUEUE = "https://sqs.us-east-1.amazonaws.com/159014723710/smartdrive-email-changed-queue";
    }

    /**
     * Expose QueueUrls as a bean for constructor injection
     */
    @Bean
    public QueueUrls queueUrls() {
        return new QueueUrls();
    }
}
