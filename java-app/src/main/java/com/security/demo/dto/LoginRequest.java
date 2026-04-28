// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Analyzer for C, C++, C#, and Java: https://pvs-studio.com

package com.security.demo.dto;

import lombok.Data;

/**
 * DTO for login requests.
 */
@Data
public class LoginRequest {
    private String username;
}
