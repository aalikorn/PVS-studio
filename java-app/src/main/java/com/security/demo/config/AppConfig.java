package com.security.demo.config;

import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

/**
 * Application configuration class.
 * Holds configuration values for the application mode and JWT settings.
 */
@Configuration
@Getter
public class AppConfig {
    
    @Value("${app.mode:VULN}")
    private String mode;
    
    @Value("${app.jwt.weak-secret}")
    private String weakSecret;
    
    @Value("${app.jwt.strong-secret}")
    private String strongSecret;
    
    @Value("${app.jwt.expiration:86400000}")
    private long jwtExpiration;
    
    /**
     * Check if application is running in vulnerable mode.
     * 
     * @return true if mode is VULN, false otherwise
     */
    public boolean isVulnerableMode() {
        return "VULN".equalsIgnoreCase(mode);
    }
    
    /**
     * Check if application is running in fixed mode.
     * 
     * @return true if mode is FIXED, false otherwise
     */
    public boolean isFixedMode() {
        return "FIXED".equalsIgnoreCase(mode);
    }
}
