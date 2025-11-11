package com.example.demo.controller;

import com.example.demo.config.auth.PrincipalDetails;
import com.example.demo.domain.dtos.UserDto;
import com.example.demo.domain.entity.User;
import com.example.demo.domain.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

import java.io.IOException;

@Controller
@Slf4j
public class UserController {

    @Autowired
    private HttpServletResponse response;
    @Autowired
    private HttpServletRequest request;

    @GetMapping("/login")
    public void login(@AuthenticationPrincipal PrincipalDetails principalDetails) throws IOException {
        log.info("GET /login....");
        String endPoint = request.getRequestURI();
        if(principalDetails!=null)
            response.sendRedirect("/user");
    }

    // 사용자 계정 확인방법 - 1 Autentication Bean 주입
//    @GetMapping("/user")
//    public void user(Authentication authentication, Model model){
//        log.info("GET /user...."+authentication);
//        log.info("name : "+authentication.getName());
//        log.info("principal : "+authentication.getPrincipal());
//        log.info("authoritites : "+authentication.getAuthorities());
//        log.info("details : "+authentication.getDetails());
//        log.info("credential : "+authentication.getCredentials());
//
//        model.addAttribute("auth_1",authentication);
//    }

    // 사용자 계정 확인방법 - 2
    @GetMapping("/user")
    public void user(Model model){

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        log.info("GET /user...."+authentication);
        log.info("name : "+authentication.getName());
        log.info("principal : "+authentication.getPrincipal());
        log.info("authoritites : "+authentication.getAuthorities());
        log.info("details : "+authentication.getDetails());
        log.info("credential : "+authentication.getCredentials());

        model.addAttribute("auth_1",authentication);
    }

    // 확인 방법 -3 Authentication's Principal 만 꺼내와 연결
    @GetMapping("/manager")
    public void manager(@AuthenticationPrincipal PrincipalDetails principalDetails, Model model){
        log.info("GET /manager...."+principalDetails);

        model.addAttribute("",principalDetails);
    }

    @GetMapping("/admin")
    public void admin(){
        log.info("GET /admin....");
    }

    @GetMapping("/join")
    public void join(){
        log.info("GET /join....");
    }

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private UserRepository userRepository;

    @PostMapping("/join")
    public String join_post(UserDto dto){
        log.info("POST /join...."+dto);
        String pwd=passwordEncoder.encode(dto.getPassword()); //패스워드 암호화 저장
        //dto -> entity
        User user=new User();
        user.setUsername(dto.getUsername());
        user.setPassword(pwd);
        user.setRole("ROLE_USER"); // DB = ROLE_USER
        userRepository.save(user);

        boolean isJoin=true;
        if(isJoin){
            return "redirect:/login";
        }
        return "join";
    }
}
