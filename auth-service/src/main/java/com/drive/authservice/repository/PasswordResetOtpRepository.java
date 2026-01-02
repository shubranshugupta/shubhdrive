package com.drive.authservice.repository;

import com.drive.authservice.entity.PasswordResetOTP;
import com.drive.authservice.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface PasswordResetOtpRepository extends JpaRepository<PasswordResetOTP, Long> {
    
    Optional<PasswordResetOTP> findByUser(User user);

    // This tells Spring: "Go into the 'User' field, and match the 'Email' property inside it"
    Optional<PasswordResetOTP> findByUser_Email(String email);
}