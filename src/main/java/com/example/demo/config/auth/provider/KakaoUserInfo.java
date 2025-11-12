package com.example.demo.config.auth.provider;


import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.Map;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class KakaoUserInfo implements OAuth2UserInfo{
    //카카오 전용 속성
    private Long id;
    private LocalDateTime connected_at;
    private Map<String,Object> properties;
    private Map<String,Object> kakao_account;

    //내용추출위한 공통화된 함수
    @Override
    public String getName() {
        return (String)properties.get("nickname");
    }

    @Override
    public String getEmail() {
        return (String)kakao_account.get("email");
    }

    @Override
    public String getProvider() {
        return "Kakao";
    }

    @Override
    public String getProviderId() {
        return id!=null ? id.toString() : "0";
    }

    @Override
    public Map<String, Object> getAttributes() {
        return kakao_account;
    }
}
