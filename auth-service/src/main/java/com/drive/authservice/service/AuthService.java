package com.drive.authservice.service;

import lombok.*;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Service;

import com.drive.authservice.repository.UserRepository;
import com.drive.authservice.dto.*;
import com.drive.authservice.entity.RefreshToken;
import com.drive.authservice.entity.Role;
import com.drive.authservice.entity.User;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final UserRepository userRepository;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final OtpService otpService;

    public LoginResponse login(LoginRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );

        User user = userRepository.findByEmail(request.getEmail())
                .or(() -> userRepository.findByUsername(request.getEmail()))
                .orElseThrow(() -> new RuntimeException("User not found"));
        
        if(user.getRole().equals(Role.ADMIN) && user.isFirstLogin()) {
            return LoginResponse.builder()
                    .status("ADMIN_SETUP_REQUIRED")
                    .message("Default admin detected. Please complete setup (Set Email & Password).")
                    .build();
        }

        if(user.getRole().equals(Role.USER) && user.isFirstLogin()) {
            otpService.generateAndSendOtp(user);
            return LoginResponse.builder()
                    .status("ACTIVATION_REQUIRED")
                    .message("Account valid. OTP sent to registered email.")
                    .build();
        }

        return generateTokensAndResponse(user, "Login successful");
    }

    private LoginResponse generateTokensAndResponse(User user, String message) {
        String accessToken = jwtService.generateToken(user);
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user.getEmail());

        return LoginResponse.builder()
                .status("SUCCESS")
                .message(message)
                .accessToken(accessToken)
                .refreshToken(refreshToken.getToken())
                .build();
    }
}
