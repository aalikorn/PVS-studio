// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Analyzer for C, C++, C#, and Java: https://pvs-studio.com

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
