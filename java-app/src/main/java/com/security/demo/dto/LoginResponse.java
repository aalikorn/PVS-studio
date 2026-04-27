package com.security.demo.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

/**
 * DTO for login responses.
 */
@Data
@AllArgsConstructor
public class LoginResponse {
    private String access_token;
}
