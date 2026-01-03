package com.drive.authservice.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class UserActivationRequest {

    @NotBlank(message = "Username is required")
    private String username;

    @NotBlank(message = "Temporary password is required")
    private String tempPassword;

    @NotBlank(message = "OTP is required")
    private String otp;

    @NotBlank(message = "New password is required")
    @Size(min = 8, message = "Password must be at least 8 characters")
    @Pattern(regexp = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z]).{8,}$", 
             message = "Password must contain uppercase, lowercase, and numbers")
    private String newPassword;
}
