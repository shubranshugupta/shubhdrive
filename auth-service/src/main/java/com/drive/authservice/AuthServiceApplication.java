package com.drive.authservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

import com.drive.authservice.properties.AuthProperties;

//TODO: Write Meaningfull Exception and its Handling Mechanism
//TODO: Add Logging Mechanism
//TODO: Rate Limiting (ip, username) for Brute Force Protection, DDOS Protection
@SpringBootApplication
@EnableConfigurationProperties(AuthProperties.class)
public class AuthServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthServiceApplication.class, args);
    }

}
