// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Analyzer for C, C++, C#, and Java: https://pvs-studio.com

package com.security.demo.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Map;

/**
 * DTO for user documents response.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserDocsResponse {
    private Long requested_user_id;
    private String username;
    private List<String> docs;
    private Map<String, Object> token_payload;
}
