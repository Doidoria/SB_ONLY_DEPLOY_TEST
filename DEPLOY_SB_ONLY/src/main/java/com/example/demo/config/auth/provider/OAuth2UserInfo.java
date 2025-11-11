package com.example.demo.config.auth.provider;

import java.util.Map;

public interface OAuth2UserInfo {
    String getName(); // 이름 반환
    String getEmail(); // 접속 이메일 계정 반환
    String getProvider(); // PROVIDER 이름 반환
    String getProviderId();
    Map<String, Object> getAttributes(); // !계정 정보 반환
}
