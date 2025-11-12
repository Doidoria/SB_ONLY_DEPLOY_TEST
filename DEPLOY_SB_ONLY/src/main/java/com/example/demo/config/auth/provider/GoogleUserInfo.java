package com.example.demo.config.auth.provider;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class GoogleUserInfo implements OAuth2UserInfo{
    private Map<String,Object> attributes;

    @Override
    public String getName() {
        return (String)attributes.get("given_name");
    }

    @Override
    public String getEmail() {
        return (String)attributes.get("email");
    }

    @Override
    public String getProvider() {
        return "Google";
    }

    @Override
    public String getProviderId() {
        return (String)attributes.get("sub");
    }
}
