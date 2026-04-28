// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Analyzer for C, C++, C#, and Java: https://pvs-studio.com

package com.security.demo.security;

import com.security.demo.config.AppConfig;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * Utility class for JWT token operations.
 * 
 * VULNERABILITY DEMONSTRATION:
 * - In VULN mode: Uses weak secret and accepts unsigned tokens
 * - In FIXED mode: Uses strong secret and validates signatures properly
 */
@Component
public class JwtUtil {
    
    private static final Logger logger = LoggerFactory.getLogger(JwtUtil.class);
    
    private final AppConfig appConfig;
    
    public JwtUtil(AppConfig appConfig) {
        this.appConfig = appConfig;
    }
    
    /**
     * Create JWT token for a user.
     * 
     * VULNERABILITY (VULN mode): Uses weak secret key
     * FIX (FIXED mode): Uses strong secret key
     * 
     * @param userId the user ID
     * @param username the username
     * @param role the user role
     * @return JWT token string
     */
    public String createToken(Long userId, String username, String role) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("user_id", userId);
        claims.put("username", username);
        claims.put("role", role);
        
        Date now = new Date();
        Date expiration = new Date(now.getTime() + appConfig.getJwtExpiration());
        
        String secret = appConfig.isVulnerableMode() 
            ? appConfig.getWeakSecret() 
            : appConfig.getStrongSecret();
        
        SecretKey key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        
        return Jwts.builder()
                .claims(claims)
                .issuedAt(now)
                .expiration(expiration)
                .signWith(key, Jwts.SIG.HS256)
                .compact();
    }
    
    /**
     * Decode and validate JWT token.
     * 
     * CRITICAL VULNERABILITY (VULN mode): 
     * - Skips signature verification using unsecured parser
     * - Accepts tokens with alg=none
     * - This allows attackers to forge tokens
     * 
     * FIX (FIXED mode):
     * - Strictly validates signature with strong secret
     * - Rejects unsigned tokens
     * - Validates token structure and expiration
     * 
     * @param token the JWT token to decode
     * @return Claims object containing token payload, or null if invalid
     */
    public Claims decodeToken(String token) {
        if (token == null || token.isEmpty()) {
            return null;
        }
        
        try {
            if (appConfig.isVulnerableMode()) {
                // VULNERABILITY: Skip signature verification
                // This is intentionally insecure for demonstration purposes
                logger.warn("VULN MODE: Decoding token without signature verification");
                
                // Parse without verification - accepts any token including alg=none
                return Jwts.parser()
                        .unsecured()
                        .build()
                        .parseUnsecuredClaims(token)
                        .getPayload();
                        
            } else {
                // FIXED: Properly validate signature
                logger.debug("FIXED MODE: Validating token signature");
                
                SecretKey key = Keys.hmacShaKeyFor(
                    appConfig.getStrongSecret().getBytes(StandardCharsets.UTF_8)
                );
                
                return Jwts.parser()
                        .verifyWith(key)
                        .build()
                        .parseSignedClaims(token)
                        .getPayload();
            }
        } catch (JwtException e) {
            logger.error("JWT validation failed: {}", e.getMessage());
            return null;
        }
    }
    
    /**
     * Extract user ID from token claims.
     * 
     * @param claims the JWT claims
     * @return user ID or null if not present
     */
    public Long getUserId(Claims claims) {
        if (claims == null) {
            return null;
        }
        Object userId = claims.get("user_id");
        if (userId instanceof Integer) {
            return ((Integer) userId).longValue();
        } else if (userId instanceof Long) {
            return (Long) userId;
        }
        return null;
    }
    
    /**
     * Extract username from token claims.
     * 
     * @param claims the JWT claims
     * @return username or null if not present
     */
    public String getUsername(Claims claims) {
        return claims != null ? claims.get("username", String.class) : null;
    }
    
    /**
     * Extract role from token claims.
     * 
     * @param claims the JWT claims
     * @return role or null if not present
     */
    public String getRole(Claims claims) {
        return claims != null ? claims.get("role", String.class) : null;
    }
}
