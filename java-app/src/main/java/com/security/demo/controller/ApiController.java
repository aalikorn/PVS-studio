package com.security.demo.controller;

import com.security.demo.config.AppConfig;
import com.security.demo.dto.*;
import com.security.demo.model.Document;
import com.security.demo.model.User;
import com.security.demo.repository.UserRepository;
import com.security.demo.security.JwtUtil;
import io.jsonwebtoken.Claims;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Main API controller for the IDOR and JWT vulnerability demonstration.
 * 
 * This controller implements endpoints that demonstrate:
 * 1. IDOR vulnerability in getUserDocs endpoint
 * 2. Weak JWT handling in authentication
 */
@RestController
@RequestMapping("")
public class ApiController {
    
    private static final Logger logger = LoggerFactory.getLogger(ApiController.class);
    
    private final AppConfig appConfig;
    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;
    
    public ApiController(AppConfig appConfig, UserRepository userRepository, JwtUtil jwtUtil) {
        this.appConfig = appConfig;
        this.userRepository = userRepository;
        this.jwtUtil = jwtUtil;
    }
    
    /**
     * Root endpoint providing API information.
     */
    @GetMapping("/")
    public ResponseEntity<Map<String, Object>> index() {
        Map<String, Object> response = new HashMap<>();
        response.put("project", "IDOR + Weak JWT demo");
        response.put("mode", appConfig.getMode());
        response.put("endpoints", Arrays.asList("/health", "/login", "/users/<id>/docs"));
        
        logger.info("Index endpoint accessed");
        return ResponseEntity.ok(response);
    }
    
    /**
     * Health check endpoint.
     */
    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> health() {
        String status = "ok";
        String dbStatus = "ok";
        
        try {
            // Simple DB connectivity check
            userRepository.count();
        } catch (Exception e) {
            status = "degraded";
            dbStatus = "error";
            logger.error("Health check DB probe failed", e);
        }
        
        Map<String, Object> response = new HashMap<>();
        response.put("status", status);
        response.put("mode", appConfig.getMode());
        response.put("db", dbStatus);
        
        HttpStatus httpStatus = "ok".equals(status) ? HttpStatus.OK : HttpStatus.SERVICE_UNAVAILABLE;
        logger.info("Health check result: {}", response);
        
        return ResponseEntity.status(httpStatus).body(response);
    }
    
    /**
     * Login endpoint - provides JWT token for username.
     * 
     * NOTE: In this demo, no password is required (intentional simplification).
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        logger.info("Login request for username: {}", request.getUsername());
        
        if (request.getUsername() == null || request.getUsername().isEmpty()) {
            return ResponseEntity.badRequest().body(new ErrorResponse("username required"));
        }
        
        Optional<User> userOpt = userRepository.findByUsername(request.getUsername());
        if (userOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new ErrorResponse("user not found"));
        }
        
        User user = userOpt.get();
        String token = jwtUtil.createToken(user.getId(), user.getUsername(), user.getRole());
        
        logger.info("Login successful for user: {} (id={})", user.getUsername(), user.getId());
        return ResponseEntity.ok(new LoginResponse(token));
    }
    
    /**
     * Get user documents endpoint.
     * 
     * CRITICAL IDOR VULNERABILITY DEMONSTRATION:
     * 
     * VULN mode:
     * - Does NOT check if the authenticated user has permission to access the requested user's documents
     * - Any authenticated user can access any other user's documents by changing the user_id in the URL
     * - This is a classic IDOR (Insecure Direct Object Reference) vulnerability
     * 
     * FIXED mode:
     * - Validates that the authenticated user is either:
     *   a) The owner of the documents (user_id matches token user_id), OR
     *   b) An admin user (role == "admin")
     * - Returns 403 Forbidden if authorization check fails
     * 
     * @param userId the user ID whose documents to retrieve
     * @param request the HTTP request containing JWT claims
     * @return user documents or error response
     */
    @GetMapping("/users/{userId}/docs")
    public ResponseEntity<?> getUserDocs(@PathVariable Long userId, HttpServletRequest request) {
        logger.info("Request for user {} documents", userId);
        
        // Check if user is authenticated
        Claims claims = (Claims) request.getAttribute("jwt_claims");
        if (claims == null) {
            logger.warn("Unauthorized access attempt to /users/{}/docs", userId);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ErrorResponse("unauthorized"));
        }
        
        // Fetch user with documents
        Optional<User> userOpt = userRepository.findByIdWithDocs(userId);
        if (userOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new ErrorResponse("user not found"));
        }
        
        User user = userOpt.get();
        Long tokenUserId = jwtUtil.getUserId(claims);
        String tokenRole = jwtUtil.getRole(claims);
        
        if (appConfig.isVulnerableMode()) {
            // VULNERABILITY: No authorization check - IDOR vulnerability
            // Any authenticated user can access any other user's documents
            logger.warn("VULN MODE: Returning documents without authorization check (IDOR vulnerability)");
            
            List<String> docNames = user.getDocs().stream()
                    .map(Document::getFilename)
                    .collect(Collectors.toList());
            
            // Include token payload in response for demonstration
            Map<String, Object> tokenPayload = new HashMap<>();
            tokenPayload.put("user_id", tokenUserId);
            tokenPayload.put("username", jwtUtil.getUsername(claims));
            tokenPayload.put("role", tokenRole);
            
            UserDocsResponse response = new UserDocsResponse(
                user.getId(),
                user.getUsername(),
                docNames,
                tokenPayload
            );
            
            return ResponseEntity.ok(response);
        } else {
            // FIXED: Enforce authorization check
            // User can only access their own documents OR must be admin
            if (!userId.equals(tokenUserId) && !"admin".equals(tokenRole)) {
                logger.warn("FIXED MODE: Forbidden - user {} attempted to access user {}'s documents", 
                    tokenUserId, userId);
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(new ErrorResponse("forbidden"));
            }
            
            logger.info("FIXED MODE: Authorization check passed for user {}", tokenUserId);
            
            List<String> docNames = user.getDocs().stream()
                    .map(Document::getFilename)
                    .collect(Collectors.toList());
            
            UserDocsResponse response = new UserDocsResponse(
                user.getId(),
                user.getUsername(),
                docNames,
                null  // Don't expose token payload in fixed mode
            );
            
            return ResponseEntity.ok(response);
        }
    }
}
