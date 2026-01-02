package com.drive.authservice.service;

import com.drive.authservice.entity.PasswordResetOTP;
import com.drive.authservice.entity.User;
import com.drive.authservice.repository.PasswordResetOtpRepository;
import com.drive.authservice.repository.UserRepository;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Map;

//TODO: Fix Password Reset Service
@Service
@RequiredArgsConstructor
public class PasswordResetService {

    private final PasswordResetOtpRepository otpRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    // 1. Verify OTP
    public String verifyOtp(String email, String rawOtp) {
        // FIX: Changed method name to findByUser_Email to match Repository
        PasswordResetOTP otpEntity = otpRepository.findByUser_Email(email)
            .orElseThrow(() -> new RuntimeException("Invalid Request"));

        // Check Expiry
        if (otpEntity.getExpiryTime().isBefore(LocalDateTime.now())) {
            otpRepository.delete(otpEntity); 
            throw new RuntimeException("OTP Expired");
        }

        // Check attempts limit
        if (otpEntity.getAttempts() >= 3) {
            otpRepository.delete(otpEntity); 
            throw new RuntimeException("Too many failed attempts. Request a new OTP.");
        }

        // Check Match
        if (!passwordEncoder.matches(rawOtp, otpEntity.getOtpHash())) {
            incrementAttempts(otpEntity);
            throw new RuntimeException("Invalid OTP");
        }

        // SUCCESS
        User user = userRepository.findByEmail(email).orElseThrow();
        String resetToken = jwtService.generateToken(Map.of("type", "RESET"), user);
        
        otpRepository.delete(otpEntity);
        
        return resetToken;
    }

    // 2. Reset Password
    public void resetPassword(String resetToken, String newPassword) {
        String email = jwtService.extractEmail(resetToken);
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (!jwtService.isTokenValid(resetToken, user)) {
            throw new RuntimeException("Invalid Token");
        }
        
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
    }
    
    public String generateOtp() {
        SecureRandom random = new SecureRandom();
        int otp = 100000 + random.nextInt(900000);
        return String.valueOf(otp);
    }

    private void incrementAttempts(PasswordResetOTP otpEntity) {
        otpEntity.setAttempts(otpEntity.getAttempts() + 1);
        otpRepository.save(otpEntity);
    }
}