package com.drive.authservice.service;

import com.drive.authservice.dto.LoginResponse;
import com.drive.authservice.entity.RefreshToken;
import com.drive.authservice.entity.User;
import com.drive.authservice.repository.RefreshTokenRepository;
import com.drive.authservice.repository.UserRepository;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

//TODO: Fix Refresh Token Service
@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    @Value("${auth.token.refresh-expiration}")
    private long REFRESH_EXPIRATION;

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final JwtService jwtService;

    public RefreshToken createRefreshToken(String username) {
        User user = userRepository.findByEmail(username)
                .orElseThrow(() -> new RuntimeException("User not found: " + username));

        // 1. Check if a token already exists for this user
        RefreshToken refreshToken = refreshTokenRepository.findByUser(user)
                .orElse(
                    // 2. If NOT exists, create a new builder
                    RefreshToken.builder()
                        .user(user)
                        .build()
                );

        // 3. Update the existing (or new) token with a fresh UUID and Expiry
        refreshToken.setToken(UUID.randomUUID().toString());
        refreshToken.setExpiryDate(Instant.now().plusMillis(REFRESH_EXPIRATION));

        return refreshTokenRepository.save(refreshToken);
    }

    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token.getExpiryDate().compareTo(Instant.now()) < 0) {
            refreshTokenRepository.delete(token);
            throw new RuntimeException("Refresh token was expired. Please make a new login request");
        }
        return token;
    }

    /**
     * Revokes a refresh token (Used for Logout).
     */
    public void revokeToken(String token, HttpServletResponse httpResponse) {
        refreshTokenRepository.findByToken(token)
                .ifPresent(refreshTokenRepository::delete);

        // B. Clear the Cookie (Overwrite with null and 0 maxAge)
        Cookie cookie = new Cookie("refreshToken", null);
        cookie.setHttpOnly(true);
        //TODO: Set to true in production
        cookie.setSecure(false);
        cookie.setPath("/");
        cookie.setMaxAge(0); // Expires immediately
        httpResponse.addCookie(cookie);
    }

    @Transactional // Ensure delete and save happen in one transaction
    public LoginResponse processRefreshToken(String requestToken, HttpServletResponse httpResponse) {
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

        Cookie refreshCookie = new Cookie("refreshToken", newRefresh.getToken());
        refreshCookie.setHttpOnly(true);
        // TODO: Set to true in production
        refreshCookie.setSecure(false);
        refreshCookie.setPath("/");
        refreshCookie.setMaxAge((int) REFRESH_EXPIRATION / 1000); // 7 days
        httpResponse.addCookie(refreshCookie);

        // 5. Return Response
        return LoginResponse.builder()
                .accessToken(newAccess)
                .status("SUCCESS")
                .message("Token refreshed successfully")
                .build();
    }
}