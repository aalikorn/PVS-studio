// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Analyzer for C, C++, C#, and Java: https://pvs-studio.com

package com.security.demo.security;

import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Filter to extract and validate JWT tokens from requests.
 * Adds JWT claims to request attributes for use in controllers.
 */
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    
    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    
    private final JwtUtil jwtUtil;
    
    public JwtAuthenticationFilter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                   HttpServletResponse response, 
                                   FilterChain filterChain) 
            throws ServletException, IOException {
        
        String authHeader = request.getHeader(AUTHORIZATION_HEADER);
        
        if (authHeader != null && authHeader.startsWith(BEARER_PREFIX)) {
            String token = authHeader.substring(BEARER_PREFIX.length());
            Claims claims = jwtUtil.decodeToken(token);
            
            if (claims != null) {
                // Store claims in request attributes for controller access
                request.setAttribute("jwt_claims", claims);
                request.setAttribute("jwt_user_id", jwtUtil.getUserId(claims));
                request.setAttribute("jwt_username", jwtUtil.getUsername(claims));
                request.setAttribute("jwt_role", jwtUtil.getRole(claims));
                
                logger.debug("JWT authenticated: user_id={}, username={}, role={}", 
                    jwtUtil.getUserId(claims),
                    jwtUtil.getUsername(claims),
                    jwtUtil.getRole(claims));
            }
        }
        
        filterChain.doFilter(request, response);
    }
}
