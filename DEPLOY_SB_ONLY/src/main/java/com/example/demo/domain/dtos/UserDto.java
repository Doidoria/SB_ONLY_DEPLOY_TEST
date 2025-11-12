package com.example.demo.domain.dtos;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserDto {
    private String username;
    private String password;
    private String role;

    public UserDto(String username,String password,String role){
        this.username = username;
        this.password = password;
        this.role = role;
    }

    //OAuth2 Client Info
    private String provider;
    private String providerId;
}
