package com.smartdrive.authservice.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

/**
 * DTO for login requests from the UI
 */
@Data
public class LoginRequest {

    @NotBlank(message = "Username or email is required")
    private String usernameOrEmail;

    @NotBlank(message = "Password is required")
    private String password;

    private boolean rememberMe = false;
}
