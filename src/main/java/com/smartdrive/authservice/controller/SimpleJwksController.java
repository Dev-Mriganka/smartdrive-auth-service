package com.smartdrive.authservice.controller;

import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.smartdrive.authservice.config.JwtKeyConfig;
import com.nimbusds.jose.jwk.RSAKey;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import java.util.HashMap;
import java.util.Map;
import java.util.List;

/**
 * Simple JWKS Controller for JWT validation
 * Provides the JWKS endpoint without full OAuth2 infrastructure
 */
@RestController
@RequestMapping("/oauth2")
@Profile("docker")
@RequiredArgsConstructor
@Slf4j
public class SimpleJwksController {

    private final JwtKeyConfig jwtKeyConfig;

    /**
     * JWKS endpoint for JWT validation
     */
    @GetMapping("/jwks")
    public ResponseEntity<Map<String, Object>> getJwks() {
        log.info("🔑 JWKS endpoint requested");
        try {
            RSAKey rsaKey = jwtKeyConfig.getRsaKey();
            
            // Create clean JWK response with only required fields
            Map<String, Object> jwk = new HashMap<>();
            jwk.put("kty", "RSA");
            jwk.put("e", rsaKey.getPublicExponent().toString());
            jwk.put("n", rsaKey.getModulus().toString());
            jwk.put("kid", rsaKey.getKeyID());
            jwk.put("use", "sig");
            jwk.put("alg", "RS256");
            
            Map<String, Object> response = new HashMap<>();
            response.put("keys", List.of(jwk));
            
            log.debug("✅ JWKS returned successfully");
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("❌ Error generating JWKS: {}", e.getMessage(), e);
            return ResponseEntity.internalServerError().build();
        }
    }
}
