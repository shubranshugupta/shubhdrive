package com.drive.authservice.controller;

import lombok.*;
import jakarta.validation.*;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.drive.authservice.dto.LoginResponse;
import com.drive.authservice.service.AuthService;
import com.drive.authservice.service.RefreshTokenService;
import com.drive.authservice.dto.LoginRequest;


@RestController
@RequestMapping({"api/v1/auth", "api/auth"})
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;
    private final RefreshTokenService refreshTokenService;

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody @Valid LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    //TODO: "/admin/setup", "/activate", "/refresh", "/logout" endpoints to be implemented
}
