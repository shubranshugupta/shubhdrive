package com.drive.authservice.service;

import com.drive.authservice.entity.PasswordResetOTP;
import com.drive.authservice.entity.User;
import com.drive.authservice.repository.PasswordResetOtpRepository;

import lombok.RequiredArgsConstructor;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class OtpService {

    private final PasswordResetOtpRepository otpRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public void generateAndSendOtp(User user) {
        // 1. Clean up any existing OTP for this user to prevent clutter
        otpRepository.findByUser(user).ifPresent(otpRepository::delete);

        // 2. Generate 6-digit Code
        String rawOtp = generateRandomOtp();

        // 3. Create Entity (Hash the OTP for security, even in test mode)
        PasswordResetOTP otpEntity = PasswordResetOTP.builder()
                .user(user)
                .otpHash(passwordEncoder.encode(rawOtp)) // Securely hashed
                .expiryTime(LocalDateTime.now().plusMinutes(5)) // Valid for 5 mins
                .attempts(0)
                .isUsed(false)
                .build();

        // 4. Save to DB
        otpRepository.save(otpEntity);

        // 5. "Send" (Console Print)
        // TODO: Replace with real email service in production
        System.out.println("\n==================================================");
        System.out.println(" [DEV-MODE] OTP for User: " + user.getUsername());
        System.out.println(" [DEV-MODE] Code: " + rawOtp);
        System.out.println("==================================================\n");
    }

    /**
     * Validates the OTP. Returns true if valid, false otherwise.
     * Manages attempt counting.
     */
    public int validateOtp(User user, String inputOtp) {
        var otpOptional = otpRepository.findByUser(user);

        // 1. Check if exists
        if (otpOptional.isEmpty()) {
            return 1;
        }

        PasswordResetOTP otpEntity = otpOptional.get();

        // 2. Check Expiry
        if (otpEntity.getExpiryTime().isBefore(LocalDateTime.now())) {
            otpRepository.delete(otpEntity);
            return 1;
        }

        // 3. Check Match
        if (passwordEncoder.matches(inputOtp, otpEntity.getOtpHash())) {
            // Success: Clean up and return true
            otpRepository.delete(otpEntity);
            return 0;
        } else {
            otpEntity.setAttempts(otpEntity.getAttempts() + 1);
            if (otpEntity.getAttempts() > 3) {
                otpRepository.delete(otpEntity);
                return 2;
            } else {
                otpRepository.save(otpEntity);
            }
            return 1;
        }
    }

    private String generateRandomOtp() {
        SecureRandom random = new SecureRandom();
        int otp = 100000 + random.nextInt(900000);
        return String.valueOf(otp);
    }
}