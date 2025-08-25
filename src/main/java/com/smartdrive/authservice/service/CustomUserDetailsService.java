package com.smartdrive.authservice.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collections;

@Service
@RequiredArgsConstructor
@Slf4j
public class CustomUserDetailsService implements UserDetailsService {



    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        log.info("🚀 Loading user by username: {}", username);
        
        try {
            // For OAuth2, we don't need to load user details here
            // The actual user verification happens in the User Service
            // This is just a placeholder for Spring Security
            
            return User.builder()
                    .username(username)
                    .password("") // Password will be verified by User Service
                    .authorities(Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")))
                    .accountExpired(false)
                    .accountLocked(false)
                    .credentialsExpired(false)
                    .disabled(false)
                    .build();
                    
        } catch (Exception e) {
            log.warn("📥 User not found: {}", username);
            throw new UsernameNotFoundException("User not found: " + username);
        }
    }
}
