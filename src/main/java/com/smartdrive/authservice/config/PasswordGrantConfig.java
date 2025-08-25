package com.smartdrive.authservice.config;

import com.smartdrive.authservice.client.UserServiceClient;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Collections;

@Configuration
@RequiredArgsConstructor
@Slf4j
public class PasswordGrantConfig {

    private final UserServiceClient userServiceClient;

    @Bean
    public AuthenticationProvider passwordGrantAuthenticationProvider() {
        return new AuthenticationProvider() {
            @Override
            public Authentication authenticate(Authentication authentication) throws AuthenticationException {
                String username = authentication.getName();
                String password = authentication.getCredentials().toString();
                
                log.info("🔐 Authenticating user with password grant: {}", username);
                
                // Verify credentials with User Service
                boolean isValid = userServiceClient.verifyCredentials(username, password);
                
                if (isValid) {
                    // Create user details
                    UserDetails userDetails = User.builder()
                            .username(username)
                            .password("") // We don't store the password
                            .authorities(Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")))
                            .accountExpired(false)
                            .accountLocked(false)
                            .credentialsExpired(false)
                            .disabled(false)
                            .build();
                    
                    log.info("✅ Password grant authentication successful for user: {}", username);
                    return new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                } else {
                    log.warn("❌ Password grant authentication failed for user: {}", username);
                    return null;
                }
            }

            @Override
            public boolean supports(Class<?> authentication) {
                return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
            }
        };
    }
}
