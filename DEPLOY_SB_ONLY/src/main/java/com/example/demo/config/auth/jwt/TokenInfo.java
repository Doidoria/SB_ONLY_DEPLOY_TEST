package com.example.demo.config.auth.jwt;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;




@AllArgsConstructor
@NoArgsConstructor
@Builder
@Data
public class TokenInfo {
    private String grantType;
    private String accessToken;
    private String refreshToken;
}
