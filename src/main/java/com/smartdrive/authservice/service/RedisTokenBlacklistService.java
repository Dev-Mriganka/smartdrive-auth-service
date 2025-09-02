package com.smartdrive.authservice.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.TimeUnit;

/**
 * Redis-based Token Blacklist Service
 * 
 * Manages token blacklisting using Redis for distributed session management.
 * This replaces the in-memory approach with a scalable Redis-based solution.
 * 
 * Features:
 * - Token blacklisting with automatic expiration
 * - JWT validation caching
 * - Session management support
 * - Distributed scalability
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class RedisTokenBlacklistService {

    private final RedisTemplate<String, Object> redisTemplate;
    private final JwtDecoder jwtDecoder;

    private static final String BLACKLIST_PREFIX = "authservice:blacklist:";
    private static final String REFRESH_TOKEN_PREFIX = "authservice:refresh:";
    private static final String JWT_CACHE_PREFIX = "authservice:jwt:";
    private static final String SESSION_PREFIX = "authservice:session:";

    /**
     * Blacklist an access token
     * Token will be automatically removed when it expires
     */
    public void blacklistAccessToken(String accessToken) {
        try {
            Jwt jwt = jwtDecoder.decode(accessToken);
            String tokenId = jwt.getId(); // jti claim
            Instant expiry = jwt.getExpiresAt();
            
            if (tokenId != null && expiry != null) {
                String key = BLACKLIST_PREFIX + "access:" + tokenId;
                long ttlSeconds = Duration.between(Instant.now(), expiry).getSeconds();
                
                if (ttlSeconds > 0) {
                    redisTemplate.opsForValue().set(key, "blacklisted", ttlSeconds, TimeUnit.SECONDS);
                    log.debug("🚫 Access token blacklisted: {} (TTL: {}s)", tokenId.substring(0, 8) + "...", ttlSeconds);
                } else {
                    log.debug("⏰ Access token already expired, skipping blacklist: {}", tokenId.substring(0, 8) + "...");
                }
            } else {
                log.warn("⚠️ Cannot blacklist token without ID or expiry");
            }
        } catch (JwtException e) {
            log.warn("⚠️ Cannot decode token for blacklisting: {}", e.getMessage());
        }
    }

    /**
     * Blacklist a refresh token
     * Uses longer TTL since refresh tokens typically have longer lifespans
     */
    public void blacklistRefreshToken(String refreshToken) {
        try {
            Jwt jwt = jwtDecoder.decode(refreshToken);
            String tokenId = jwt.getId(); // jti claim
            Instant expiry = jwt.getExpiresAt();
            
            if (tokenId != null && expiry != null) {
                String key = BLACKLIST_PREFIX + "refresh:" + tokenId;
                long ttlSeconds = Duration.between(Instant.now(), expiry).getSeconds();
                
                if (ttlSeconds > 0) {
                    redisTemplate.opsForValue().set(key, "blacklisted", ttlSeconds, TimeUnit.SECONDS);
                    log.debug("🚫 Refresh token blacklisted: {} (TTL: {}s)", tokenId.substring(0, 8) + "...", ttlSeconds);
                } else {
                    log.debug("⏰ Refresh token already expired, skipping blacklist: {}", tokenId.substring(0, 8) + "...");
                }
            } else {
                log.warn("⚠️ Cannot blacklist refresh token without ID or expiry");
            }
        } catch (JwtException e) {
            log.warn("⚠️ Cannot decode refresh token for blacklisting: {}", e.getMessage());
        }
    }

    /**
     * Check if an access token is blacklisted
     */
    public boolean isAccessTokenBlacklisted(String accessToken) {
        try {
            Jwt jwt = jwtDecoder.decode(accessToken);
            String tokenId = jwt.getId();
            
            if (tokenId != null) {
                String key = BLACKLIST_PREFIX + "access:" + tokenId;
                Boolean isBlacklisted = redisTemplate.hasKey(key);
                
                if (Boolean.TRUE.equals(isBlacklisted)) {
                    log.debug("🚫 Access token is blacklisted: {}", tokenId.substring(0, 8) + "...");
                    return true;
                }
            }
            return false;
        } catch (JwtException e) {
            log.warn("⚠️ Invalid access token format: {}", e.getMessage());
            return true; // Treat invalid tokens as blacklisted
        }
    }

    /**
     * Check if a refresh token is blacklisted
     */
    public boolean isRefreshTokenBlacklisted(String refreshToken) {
        try {
            Jwt jwt = jwtDecoder.decode(refreshToken);
            String tokenId = jwt.getId();
            
            if (tokenId != null) {
                String key = BLACKLIST_PREFIX + "refresh:" + tokenId;
                Boolean isBlacklisted = redisTemplate.hasKey(key);
                
                if (Boolean.TRUE.equals(isBlacklisted)) {
                    log.debug("🚫 Refresh token is blacklisted: {}", tokenId.substring(0, 8) + "...");
                    return true;
                }
            }
            return false;
        } catch (JwtException e) {
            log.warn("⚠️ Invalid refresh token format: {}", e.getMessage());
            return true; // Treat invalid tokens as blacklisted
        }
    }

    /**
     * Check if any token (access or refresh) is blacklisted
     * This is the main method used by the validation endpoint
     */
    public boolean isTokenBlacklisted(String token) {
        try {
            Jwt jwt = jwtDecoder.decode(token);
            String tokenId = jwt.getId();
            String tokenType = jwt.getClaimAsString("token_type");

            if (tokenId == null) {
                return false;
            }

            String key;
            if ("refresh".equals(tokenType)) {
                key = BLACKLIST_PREFIX + "refresh:" + tokenId;
            } else {
                key = BLACKLIST_PREFIX + "access:" + tokenId;
            }

            Boolean isBlacklisted = redisTemplate.hasKey(key);
            return Boolean.TRUE.equals(isBlacklisted);

        } catch (JwtException e) {
            log.warn("⚠️ Cannot decode token for blacklist check: {}", e.getMessage());
            return true; // Treat invalid tokens as blacklisted
        }
    }

    /**
     * Cache JWT validation result to improve performance
     * Caches valid JWTs for a short period to avoid repeated decoding
     */
    public void cacheJwtValidation(String token, boolean isValid) {
        try {
            String tokenHash = String.valueOf(token.hashCode());
            String key = JWT_CACHE_PREFIX + tokenHash;
            
            // Cache validation result for 5 minutes
            redisTemplate.opsForValue().set(key, isValid, 300, TimeUnit.SECONDS);
            log.debug("💾 JWT validation cached: {} -> {}", tokenHash, isValid);
        } catch (Exception e) {
            log.warn("⚠️ Failed to cache JWT validation: {}", e.getMessage());
        }
    }

    /**
     * Get cached JWT validation result
     * Returns null if not cached
     */
    public Boolean getCachedJwtValidation(String token) {
        try {
            String tokenHash = String.valueOf(token.hashCode());
            String key = JWT_CACHE_PREFIX + tokenHash;
            
            Object cached = redisTemplate.opsForValue().get(key);
            if (cached instanceof Boolean) {
                log.debug("💾 JWT validation retrieved from cache: {} -> {}", tokenHash, cached);
                return (Boolean) cached;
            }
            return null;
        } catch (Exception e) {
            log.warn("⚠️ Failed to retrieve cached JWT validation: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Store refresh token metadata in Redis
     * Useful for tracking token usage and implementing refresh token rotation
     */
    public void storeRefreshTokenMetadata(String refreshToken, String userId) {
        try {
            Jwt jwt = jwtDecoder.decode(refreshToken);
            String tokenId = jwt.getId();
            Instant expiry = jwt.getExpiresAt();
            
            if (tokenId != null && expiry != null) {
                String key = REFRESH_TOKEN_PREFIX + tokenId;
                long ttlSeconds = Duration.between(Instant.now(), expiry).getSeconds();
                
                if (ttlSeconds > 0) {
                    RefreshTokenMetadata metadata = new RefreshTokenMetadata();
                    metadata.setUserId(userId);
                    metadata.setIssuedAt(Instant.now());
                    metadata.setExpiresAt(expiry);
                    metadata.setLastUsed(Instant.now());
                    
                    redisTemplate.opsForValue().set(key, metadata, ttlSeconds, TimeUnit.SECONDS);
                    log.debug("💾 Refresh token metadata stored: {}", tokenId.substring(0, 8) + "...");
                }
            }
        } catch (JwtException e) {
            log.warn("⚠️ Failed to store refresh token metadata: {}", e.getMessage());
        }
    }

    /**
     * Get refresh token metadata
     */
    public RefreshTokenMetadata getRefreshTokenMetadata(String refreshToken) {
        try {
            Jwt jwt = jwtDecoder.decode(refreshToken);
            String tokenId = jwt.getId();
            
            if (tokenId != null) {
                String key = REFRESH_TOKEN_PREFIX + tokenId;
                Object metadata = redisTemplate.opsForValue().get(key);
                
                if (metadata instanceof RefreshTokenMetadata) {
                    return (RefreshTokenMetadata) metadata;
                }
            }
            return null;
        } catch (JwtException e) {
            log.warn("⚠️ Failed to retrieve refresh token metadata: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Update refresh token last used timestamp
     */
    public void updateRefreshTokenLastUsed(String refreshToken) {
        try {
            RefreshTokenMetadata metadata = getRefreshTokenMetadata(refreshToken);
            if (metadata != null) {
                Jwt jwt = jwtDecoder.decode(refreshToken);
                String tokenId = jwt.getId();
                String key = REFRESH_TOKEN_PREFIX + tokenId;
                
                metadata.setLastUsed(Instant.now());
                
                Instant expiry = jwt.getExpiresAt();
                long ttlSeconds = Duration.between(Instant.now(), expiry).getSeconds();
                
                if (ttlSeconds > 0) {
                    redisTemplate.opsForValue().set(key, metadata, ttlSeconds, TimeUnit.SECONDS);
                    log.debug("🔄 Refresh token last used updated: {}", tokenId.substring(0, 8) + "...");
                }
            }
        } catch (JwtException e) {
            log.warn("⚠️ Failed to update refresh token last used: {}", e.getMessage());
        }
    }

    /**
     * Create user session in Redis
     * Useful for tracking active sessions and implementing session limits
     */
    public void createUserSession(String userId, String sessionId, String accessTokenId) {
        try {
            String key = SESSION_PREFIX + userId + ":" + sessionId;
            
            UserSession session = new UserSession();
            session.setUserId(userId);
            session.setSessionId(sessionId);
            session.setAccessTokenId(accessTokenId);
            session.setCreatedAt(Instant.now());
            session.setLastActivity(Instant.now());
            
            // Sessions expire after 8 hours of inactivity
            redisTemplate.opsForValue().set(key, session, 8, TimeUnit.HOURS);
            log.debug("🔐 User session created: {} -> {}", userId, sessionId);
        } catch (Exception e) {
            log.warn("⚠️ Failed to create user session: {}", e.getMessage());
        }
    }

    /**
     * Update session activity
     */
    public void updateSessionActivity(String userId, String sessionId) {
        try {
            String key = SESSION_PREFIX + userId + ":" + sessionId;
            Object sessionObj = redisTemplate.opsForValue().get(key);
            
            if (sessionObj instanceof UserSession) {
                UserSession session = (UserSession) sessionObj;
                session.setLastActivity(Instant.now());
                
                // Refresh TTL
                redisTemplate.opsForValue().set(key, session, 8, TimeUnit.HOURS);
                log.debug("🔄 Session activity updated: {} -> {}", userId, sessionId);
            }
        } catch (Exception e) {
            log.warn("⚠️ Failed to update session activity: {}", e.getMessage());
        }
    }

    /**
     * Invalidate user session
     */
    public void invalidateUserSession(String userId, String sessionId) {
        try {
            String key = SESSION_PREFIX + userId + ":" + sessionId;
            redisTemplate.delete(key);
            log.debug("🗑️ User session invalidated: {} -> {}", userId, sessionId);
        } catch (Exception e) {
            log.warn("⚠️ Failed to invalidate user session: {}", e.getMessage());
        }
    }

    /**
     * Invalidate all user sessions (used during email change to force re-login)
     */
    public void invalidateAllUserSessions(String userId) {
        try {
            String pattern = SESSION_PREFIX + userId + ":*";
            var keys = redisTemplate.keys(pattern);
            
            if (keys != null && !keys.isEmpty()) {
                redisTemplate.delete(keys);
                log.info("🗑️ All user sessions invalidated for user: {} (count: {})", userId, keys.size());
            } else {
                log.debug("🗑️ No active sessions found for user: {}", userId);
            }
        } catch (Exception e) {
            log.warn("⚠️ Failed to invalidate all user sessions: {}", e.getMessage());
        }
    }

    /**
     * Get all active sessions for a user
     */
    public long getActiveSessionCount(String userId) {
        try {
            String pattern = SESSION_PREFIX + userId + ":*";
            var keys = redisTemplate.keys(pattern);
            return keys != null ? keys.size() : 0;
        } catch (Exception e) {
            log.warn("⚠️ Failed to get active session count: {}", e.getMessage());
            return 0;
        }
    }

    /**
     * Clean up expired blacklisted tokens (manual cleanup if needed)
     */
    public void cleanupExpiredTokens() {
        try {
            // Redis TTL will handle automatic cleanup, but we can log statistics
            String blacklistPattern = BLACKLIST_PREFIX + "*";
            var blacklistKeys = redisTemplate.keys(blacklistPattern);
            
            String refreshPattern = REFRESH_TOKEN_PREFIX + "*";
            var refreshKeys = redisTemplate.keys(refreshPattern);
            
            String sessionPattern = SESSION_PREFIX + "*";
            var sessionKeys = redisTemplate.keys(sessionPattern);
            
            log.info("📊 Redis token statistics - Blacklisted: {}, Refresh metadata: {}, Active sessions: {}",
                    blacklistKeys != null ? blacklistKeys.size() : 0,
                    refreshKeys != null ? refreshKeys.size() : 0,
                    sessionKeys != null ? sessionKeys.size() : 0);
        } catch (Exception e) {
            log.warn("⚠️ Failed to get token statistics: {}", e.getMessage());
        }
    }

    /**
     * Refresh token metadata class
     */
    public static class RefreshTokenMetadata {
        private String userId;
        private Instant issuedAt;
        private Instant expiresAt;
        private Instant lastUsed;

        // Getters and setters
        public String getUserId() { return userId; }
        public void setUserId(String userId) { this.userId = userId; }
        
        public Instant getIssuedAt() { return issuedAt; }
        public void setIssuedAt(Instant issuedAt) { this.issuedAt = issuedAt; }
        
        public Instant getExpiresAt() { return expiresAt; }
        public void setExpiresAt(Instant expiresAt) { this.expiresAt = expiresAt; }
        
        public Instant getLastUsed() { return lastUsed; }
        public void setLastUsed(Instant lastUsed) { this.lastUsed = lastUsed; }
    }

    /**
     * User session class
     */
    public static class UserSession {
        private String userId;
        private String sessionId;
        private String accessTokenId;
        private Instant createdAt;
        private Instant lastActivity;

        // Getters and setters
        public String getUserId() { return userId; }
        public void setUserId(String userId) { this.userId = userId; }
        
        public String getSessionId() { return sessionId; }
        public void setSessionId(String sessionId) { this.sessionId = sessionId; }
        
        public String getAccessTokenId() { return accessTokenId; }
        public void setAccessTokenId(String accessTokenId) { this.accessTokenId = accessTokenId; }
        
        public Instant getCreatedAt() { return createdAt; }
        public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
        
        public Instant getLastActivity() { return lastActivity; }
        public void setLastActivity(Instant lastActivity) { this.lastActivity = lastActivity; }
    }
}
