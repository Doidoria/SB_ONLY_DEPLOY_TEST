//package com.example.demo.config.auth.jwt;
//
//
//import io.jsonwebtoken.Claims;
//import io.jsonwebtoken.JwtParser;
//import io.jsonwebtoken.Jwts;
//import org.junit.jupiter.api.Test;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.boot.test.context.SpringBootTest;
//
//import java.security.Key;
//
//import static org.junit.jupiter.api.Assertions.*;
//
//@SpringBootTest
//class JWTTokenProviderTest {
//
//    @Autowired
//    private JWTTokenProvider tokenProvider;
//
//    @Test
//    public void t1() throws Exception{
//        TokenInfo tokenInfo = tokenProvider.generateToken();
//        System.out.println(tokenInfo);
//
//        Key key = tokenProvider.getKey();
//        JwtParser parser= Jwts.parser()
//                .setSigningKey(key)
//                .build();
//
//        String accessToken = tokenInfo.getAccessToken();
//        Claims claims = parser.parseClaimsJws(accessToken).getBody();
//        String username = claims.get("username").toString();
//        String role = claims.get("role").toString();
//        System.out.println("username : "+username);
//        System.out.println("role : "+role);
//
//
//    }
//
//    @Test
//    public void t2() throws Exception{
//
//    }
//
//}