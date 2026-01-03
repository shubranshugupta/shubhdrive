package com.drive.authservice.controller;

import lombok.*;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.*;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.drive.authservice.dto.LoginResponse;
import com.drive.authservice.dto.UserActivationRequest;
import com.drive.authservice.service.AuthService;
import com.drive.authservice.service.RefreshTokenService;
import com.drive.authservice.dto.AdminSetupRequest;
import com.drive.authservice.dto.LoginRequest;


@RestController
@RequestMapping({"/api/v1/auth", "/api/auth"})
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;
    private final RefreshTokenService refreshTokenService;

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(
        @RequestBody @Valid LoginRequest request, 
        HttpServletResponse httpResponse
    ) {
        return ResponseEntity.ok(authService.login(request, httpResponse));
    }

    //TODO: "/admin/setup", "/activate", "/refresh", "/logout" endpoints to be implemented
    @PostMapping("/admin/setup")
    public ResponseEntity<LoginResponse> adminSetup(
        @RequestBody @Valid AdminSetupRequest request, 
        HttpServletResponse httpResponse
    ) {
        return ResponseEntity.ok(authService.setupAdmin(request, httpResponse));
    }

    @PostMapping("/activate")
    public ResponseEntity<LoginResponse> activateAccount(
        @RequestBody @Valid UserActivationRequest request, 
        HttpServletResponse httpResponse
    ) {
        return ResponseEntity.ok(authService.activateAccount(request, httpResponse));
    }

    // 4. Token Refresh (Secure Cookie Flow)
    @PostMapping("/refresh")
    public ResponseEntity<LoginResponse> refresh(
            @CookieValue("refreshToken") String refreshToken,
            HttpServletResponse httpResponse
    ) {
        return ResponseEntity.ok(refreshTokenService.processRefreshToken(refreshToken, httpResponse));
    }

    // 5. Logout (Secure Cookie Flow)
    @PostMapping("/logout")
    public ResponseEntity<String> logout(
            @CookieValue(name = "refreshToken", required = false) String refreshToken,
            HttpServletResponse httpResponse
    ) {
        // A. Revoke token in DB if it exists
        if (refreshToken != null) {
            refreshTokenService.revokeToken(refreshToken, httpResponse);
        }
        return ResponseEntity.ok("Logged out successfully");
    }
}
