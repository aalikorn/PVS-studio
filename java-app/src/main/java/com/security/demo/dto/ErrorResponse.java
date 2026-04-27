package com.security.demo.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

/**
 * DTO for error responses.
 */
@Data
@AllArgsConstructor
public class ErrorResponse {
    private String error;
}
