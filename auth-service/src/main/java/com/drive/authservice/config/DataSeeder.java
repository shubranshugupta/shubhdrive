package com.drive.authservice.config;

import com.drive.authservice.entity.Role;
import com.drive.authservice.entity.User;
import com.drive.authservice.properties.AuthProperties;
import com.drive.authservice.repository.UserRepository;

import lombok.RequiredArgsConstructor;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@RequiredArgsConstructor
public class DataSeeder {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthProperties authProperties;

    @Bean
    public CommandLineRunner initAdmin() {
        return args -> {
            // 1. Check if 'admin' already exists to prevent duplicates
            if (userRepository.findByUsername("admin").isEmpty()) {
                
                User admin = User.builder()
                        .username(authProperties.getAdmin().getUsername())
                        .password(passwordEncoder.encode(authProperties.getAdmin().getPassword())) // Default password
                        .email(null) // Crucial: This triggers the "Admin Setup" flow
                        .role(Role.ADMIN) // Ensure this enum/string exists in your Entity
                        .isFirstLogin(true)
                        .build();

                userRepository.save(admin);
                System.out.println("✅ Default Admin created: admin / admin");
            }
        };
    }
}