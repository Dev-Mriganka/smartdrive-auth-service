package com.smartdrive.authservice.repository;

import com.smartdrive.authservice.model.VerificationToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Repository for VerificationToken entity
 */
@Repository
public interface VerificationTokenRepository extends JpaRepository<VerificationToken, UUID> {

    /**
     * Find token by token string
     */
    Optional<VerificationToken> findByToken(String token);

    /**
     * Find tokens by user ID
     */
    List<VerificationToken> findByUserId(UUID userId);

    /**
     * Find tokens by user ID and type
     */
    List<VerificationToken> findByUserIdAndTokenType(UUID userId, String tokenType);

    /**
     * Find valid tokens by user ID and type
     */
    @Query("SELECT vt FROM VerificationToken vt WHERE vt.user.id = :userId AND vt.tokenType = :tokenType AND vt.usedAt IS NULL AND vt.expiresAt > :now")
    List<VerificationToken> findValidTokensByUserIdAndType(@Param("userId") UUID userId, @Param("tokenType") String tokenType, @Param("now") LocalDateTime now);

    /**
     * Find expired tokens
     */
    @Query("SELECT vt FROM VerificationToken vt WHERE vt.expiresAt < :now")
    List<VerificationToken> findExpiredTokens(@Param("now") LocalDateTime now);

    /**
     * Find used tokens
     */
    List<VerificationToken> findByUsedAtIsNotNull();

    /**
     * Delete expired tokens
     */
    @Modifying
    @Query("DELETE FROM VerificationToken vt WHERE vt.expiresAt < :now")
    void deleteExpiredTokens(@Param("now") LocalDateTime now);

    /**
     * Delete used tokens
     */
    @Modifying
    @Query("DELETE FROM VerificationToken vt WHERE vt.usedAt IS NOT NULL")
    void deleteUsedTokens();
}
