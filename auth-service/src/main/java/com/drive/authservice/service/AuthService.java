package com.drive.authservice.service;

import lombok.*;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.Cookie;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Service;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.beans.factory.annotation.Value;

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
    private final PasswordEncoder passwordEncoder;
    
    @Value("${auth.token.refresh-expiration}")
    private final long REFRESH_EXPIRATION;

    public LoginResponse login(LoginRequest request, HttpServletResponse httpResponse) {
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

        return generateTokensAndResponse(user, httpResponse, "Login successful");
    }

    /**
     * SCENARIO 1 RESOLUTION: Default Admin Setup
     * Sets the email and new password for the default admin, then logs them in.
     */
    @Transactional
    public LoginResponse setupAdmin(AdminSetupRequest request, HttpServletResponse httpResponse) {
        // 1. Verify credentials (admin/admin)
        authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(request.getUsername(), request.getCurrentPassword())
        );

        // 2. Find the admin user
        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new RuntimeException("Admin user not found"));

        // 3. Security Guard: Prevent re-running setup if email is already set
        if (user.getEmail() != null && !user.getEmail().isEmpty()) {
            throw new RuntimeException("Admin setup already completed. Please use login or password reset.");
        }

        // 4. Update Admin Credentials
        user.setEmail(request.getNewEmail());
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        user.setFirstLogin(false); // Mark setup as complete
        
        userRepository.save(user);

        // 5. Generate Tokens (Auto-login)
        return generateTokensAndResponse(user, httpResponse, "Admin setup complete. You are now logged in.");
    }

    /**
     * SCENARIO 2 RESOLUTION: User Activation
     * Verifies OTP, sets new password, and activates the account.
     */
    @Transactional
    public LoginResponse activateAccount(UserActivationRequest request, HttpServletResponse httpResponse) {
        // 1. Re-verify temporary credentials to ensure it's the right user
        authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(request.getUsername(), request.getTempPassword())
        );

        User user = userRepository.findByUsername(request.getUsername())
                .or(() -> userRepository.findByEmail(request.getUsername()))
                .orElseThrow(() -> new RuntimeException("User not found"));

        // 2. Verify OTP using the OtpService
        switch(otpService.validateOtp(user, request.getOtp())) {
            case 0: break; // Valid OTP
            case 1: throw new RuntimeException("Invalid or Expired OTP");
            case 2: throw new RuntimeException("Too many failed attempts. Please request a new OTP.");
        }

        // 3. Update Password & Activate
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        user.setFirstLogin(false); // Mark as active
        userRepository.save(user);

        // 4. Generate Tokens (Auto-login)
        return generateTokensAndResponse(user, httpResponse, "Account activated successfully.");
    }

    private LoginResponse generateTokensAndResponse(User user, HttpServletResponse httpResponse, String message) {
        String accessToken = jwtService.generateToken(user);
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user.getEmail());

        // Create HttpOnly Cookie for Refresh Token
        Cookie refreshCookie = new Cookie("refreshToken", refreshToken.getToken());
        refreshCookie.setHttpOnly(true); // JS cannot read this
        //TODO: Set to true in production
        refreshCookie.setSecure(false);   // HTTPS only (use false for localhost)
        refreshCookie.setPath("/");
        refreshCookie.setMaxAge((int) REFRESH_EXPIRATION / 1000); // 7 days
        httpResponse.addCookie(refreshCookie);

        return LoginResponse.builder()
                .status("SUCCESS")
                .message(message)
                .accessToken(accessToken)
                .build();
    }
}
