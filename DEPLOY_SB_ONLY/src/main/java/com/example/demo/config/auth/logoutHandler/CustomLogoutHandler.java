package com.example.demo.config.auth.logoutHandler;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class CustomLogoutHandler implements LogoutHandler {
    
    //해당 서버의 자체 로그아웃 처리
    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        log.info("CustomLogoutHandler's logout invoke..!");
//        //세션기반(기본값)
//        HttpSession session =request.getSession();
//        if(session!=null)
//            session.invalidate();

        //Token방식 -


    }
}
