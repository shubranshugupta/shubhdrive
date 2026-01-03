package com.drive.authservice.properties;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import lombok.Data;

@Data
@Configuration
@ConfigurationProperties(prefix = "auth")
public class AuthProperties {
    private Token token;
    private Cors cors;
    private Admin admin;

    @Data
    public static class Token {
        private String secretKey;
        private long jwtExpiration;
        private long refreshExpiration;
    }

    @Data
    public static class Cors {
        // defined as 'allowed-origins' in yml, maps to 'allowedOrigins' here
        private List<String> allowedOrigins; 
        private List<String> allowedMethods;
        private List<String> allowedHeaders;
    }

    @Data
    public static class Admin {
        private String username;
        private String password;
    }
}
