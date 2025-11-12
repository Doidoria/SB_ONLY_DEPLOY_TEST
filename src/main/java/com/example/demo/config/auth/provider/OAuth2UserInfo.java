package com.example.demo.config.auth.provider;

import java.util.Map;

public interface OAuth2UserInfo {
    String getName();     //이름 반환
    String getEmail();    //접속이메일계정 반환
    String getProvider(); //PROVIDER이름 반환
    String getProviderId(); //
    Map<String,Object> getAttributes(); //!계정 정보 반환
    
}
