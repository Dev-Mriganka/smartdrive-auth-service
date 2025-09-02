package com.smartdrive.authservice.repository;

import com.smartdrive.authservice.model.AuthUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Repository for AuthUser entity
 */
@Repository
public interface AuthUserRepository extends JpaRepository<AuthUser, UUID> {

    /**
     * Find user by email
     */
    Optional<AuthUser> findByEmail(String email);

    /**
     * Find user by provider and provider ID
     */
    Optional<AuthUser> findByProviderAndProviderId(String provider, String providerId);

    /**
     * Check if email exists
     */
    Boolean existsByEmail(String email);

    /**
     * Find users with expired verification tokens
     */
    @Query("SELECT u FROM AuthUser u WHERE u.emailVerified = false")
    List<AuthUser> findUnverifiedUsers();

    /**
     * Find users with failed login attempts
     */
    List<AuthUser> findByFailedLoginAttemptsGreaterThan(Integer attempts);

    /**
     * Find locked accounts
     */
    List<AuthUser> findByAccountLockedTrue();

    /**
     * Find users created after a specific date
     */
    List<AuthUser> findByCreatedAtAfter(LocalDateTime date);

    /**
     * Count users by verification status
     */
    long countByEmailVerified(Boolean emailVerified);

    /**
     * Count enabled users
     */
    long countByAccountLockedFalse();

    /**
     * Find users by provider
     */
    List<AuthUser> findByProvider(String provider);

    /**
     * Find users updated after a specific date (for consistency checks)
     */
    List<AuthUser> findByUpdatedAtAfter(LocalDateTime date);

    /**
     * Find users updated after a specific date (for email audit)
     */
    List<AuthUser> findByUpdatedAtAfter(LocalDateTime updatedAt);

    /**
     * Find users by email list (for batch lookup)
     */
    List<AuthUser> findByEmailIn(List<String> emails);

    /**
     * Count locked users
     */
    long countByAccountLocked(Boolean accountLocked);
}
