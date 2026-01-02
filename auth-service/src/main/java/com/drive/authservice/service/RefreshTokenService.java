package com.drive.authservice.service;

import com.drive.authservice.dto.LoginResponse;
import com.drive.authservice.entity.RefreshToken;
import com.drive.authservice.entity.User;
import com.drive.authservice.repository.RefreshTokenRepository;
import com.drive.authservice.repository.UserRepository;

import lombok.RequiredArgsConstructor;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional; // Important for delete/save

import java.time.Instant;
import java.util.UUID;

//TODO: Fix Refresh Token Service
@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    @Value("${auth.token.refresh-expiration}")
    private long refreshExpiration;

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final JwtService jwtService;

    public RefreshToken createRefreshToken(String username) {
        User user = userRepository.findByEmail(username)
                .orElseThrow(() -> new RuntimeException("User not found: " + username));

        RefreshToken refreshToken = RefreshToken.builder()
                .user(user)
                .token(UUID.randomUUID().toString())
                .expiryDate(Instant.now().plusMillis(refreshExpiration))
                .build();

        return refreshTokenRepository.save(refreshToken);
    }

    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token.getExpiryDate().compareTo(Instant.now()) < 0) {
            refreshTokenRepository.delete(token);
            throw new RuntimeException("Refresh token was expired. Please make a new login request");
        }
        return token;
    }

    @Transactional // Ensure delete and save happen in one transaction
    public LoginResponse processRefreshToken(String requestToken) {
        // 1. Find and Verify (Unwrap the Optional first)
        RefreshToken token = refreshTokenRepository.findByToken(requestToken)
                .map(this::verifyExpiration)
                .orElseThrow(() -> new RuntimeException("Refresh token is not in database!"));
        
        // 2. Extract User
        User user = token.getUser();

        // 3. ROTATION: Delete Old Token
        refreshTokenRepository.delete(token);

        // 4. Generate New Tokens
        String newAccess = jwtService.generateToken(user);
        RefreshToken newRefresh = createRefreshToken(user.getEmail());

        // 5. Return Response
        return LoginResponse.builder()
                .accessToken(newAccess)
                .refreshToken(newRefresh.getToken())
                .status("SUCCESS")
                .message("Token refreshed successfully")
                .build();
    }
}