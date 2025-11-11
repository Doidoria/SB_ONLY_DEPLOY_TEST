package com.example.demo.config.auth.exceptionHandler;


import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Slf4j
//@Component
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint{

    // 인증 실패시 작동하는 함수
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        log.error("CustomAuthenticationEntryPoint's commence invoke....!");
        //ROLE 별로 기본 페이지로 이동
        response.sendRedirect("/login?error="+authException.getMessage());
    }
}
