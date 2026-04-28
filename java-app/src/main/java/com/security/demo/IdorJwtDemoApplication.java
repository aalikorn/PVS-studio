// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Analyzer for C, C++, C#, and Java: https://pvs-studio.com

package com.security.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Main application class for IDOR and JWT vulnerability demonstration.
 * 
 * This application demonstrates two critical security vulnerabilities:
 * 1. IDOR (Insecure Direct Object Reference) - accessing resources without proper authorization
 * 2. Weak JWT implementation - accepting unsigned tokens or using weak secrets
 * 
 * The application can run in two modes controlled by the MODE environment variable:
 * - VULN: Vulnerable version with security flaws
 * - FIXED: Secure version with proper authorization and JWT validation
 */
@SpringBootApplication
public class IdorJwtDemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(IdorJwtDemoApplication.class, args);
    }
}
