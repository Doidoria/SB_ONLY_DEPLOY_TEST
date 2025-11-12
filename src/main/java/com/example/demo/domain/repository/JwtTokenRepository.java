package com.example.demo.domain.repository;

import com.example.demo.domain.entity.JwtToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface JwtTokenRepository extends JpaRepository<JwtToken,Long> {
    //accesstoken -> token정보삭제
    void deleteByAccessToken(String accessToken);
    //accesstoken -> token정보가져오기
    JwtToken findByAccessToken(String accessToken);
    //username -> token정보가져오기
    JwtToken findByUsername(String username);
}
