package com.example.demo.config.auth;

import com.example.demo.domain.dtos.UserDto;
import com.example.demo.domain.entity.User;
import com.example.demo.domain.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@Slf4j
public class PrincipalDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override // DB 데이터 확인(DB에 있는걸 던져줌)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("PrincipalDetailsService's loadUserByUsername : "+username);

        Optional<User> userOptional=
                userRepository.findById(username);
        if(userOptional.isEmpty()){ // DB에 있다면
            throw new UsernameNotFoundException(username+" 계정이 존재하지 않습니다"); // 예외처리로 넘어가야됨
        }
        // entity -> dto
        User user=userOptional.get();
        UserDto dto=new UserDto();
        dto.setUsername(user.getUsername());
        dto.setPassword(user.getPassword());
        dto.setRole(user.getRole());

        return new PrincipalDetails(dto); //dto만 받는 생성자 PrincipalDetails에서 만듬
    }

}
