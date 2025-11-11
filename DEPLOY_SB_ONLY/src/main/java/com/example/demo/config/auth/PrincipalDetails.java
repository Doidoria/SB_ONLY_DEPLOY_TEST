package com.example.demo.config.auth;


import com.example.demo.domain.dtos.UserDto;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class PrincipalDetails implements UserDetails, OAuth2User {
    private UserDto dto;
    Map<String, Object> attributes; //OAUTH2 속성

    public PrincipalDetails(UserDto dto){ //dto만 받는 생성자
        this.dto=dto;
    }

    @Override // role 꺼낼때 사용
    public Collection<? extends GrantedAuthority> getAuthorities() { // ? extends GrantedAuthority 클래스형으로 상속 관계에 있는 하위클래스와 처리
        Collection<GrantedAuthority> authorities=new ArrayList<>();

        // 나중에 변경해야됨 (롤이 여러개일 경우를 염두해 둬야한다) [ROLE_ADMIN, ROLE_USER]
//        authorities.add(new SimpleGrantedAuthority(dto.getRole())); //"ROLE_ADMIN,ROLE_USER"

        String roles [] = dto.getRole().split(",");
        for(String role : roles){
            authorities.add(new SimpleGrantedAuthority(role));
        }

        return authorities;
    }

    //---------------------------------------------
    // OAUTH2에 사용되는 속성 / 메서드
    //---------------------------------------------

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }
    
    //---------------------------------------------
    // 로컬인증에 사용되는 메서드
    //---------------------------------------------
    @Override
    public String getPassword() {
        return dto.getPassword();
    }

    @Override
    public String getUsername() {
        return dto.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() { // 계정의 만료 여부
        return true;
    }

    @Override
    public boolean isAccountNonLocked() { // 계정의 잠금 여부
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() { // 패스워드 만료 여부
        return true;
    }

    @Override
    public boolean isEnabled() { // 계정 사용 가능 여부
        return true;
    }

    @Override
    public String getName() {
        return "";
    }
}
