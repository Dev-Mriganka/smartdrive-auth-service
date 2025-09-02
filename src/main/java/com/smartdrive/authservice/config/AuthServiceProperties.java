package com.smartdrive.authservice.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import lombok.Data;

/**
 * Configuration properties for Auth Service
 * Follows proper configuration management practices
 */
@Component
@ConfigurationProperties(prefix = "auth")
@Data
public class AuthServiceProperties {

    private Service service = new Service();
    private Jwt jwt = new Jwt();
    private Security security = new Security();
    private Integration integration = new Integration();

    @Data
    public static class Service {
        private String name = "SmartDrive Auth Service";
        private String version = "1.0.0";
    }

    @Data
    public static class Jwt {
        private long accessTokenExpiry = 1800; // 30 minutes
        private long refreshTokenExpiry = 604800; // 7 days
    }

    @Data
    public static class Security {
        private boolean enforceEmailVerification = true;
        private int maxFailedLoginAttempts = 5;
        private long accountLockoutDuration = 3600; // 1 hour
    }

    @Data
    public static class Integration {
        private UserService userService = new UserService();
    }

    @Data
    public static class UserService {
        private String url = "http://user-service:8083";
        private long timeout = 5000;
    }
}
