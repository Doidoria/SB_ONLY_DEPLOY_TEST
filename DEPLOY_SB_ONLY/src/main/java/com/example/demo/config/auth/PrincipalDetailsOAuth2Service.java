package com.example.demo.config.auth;

import com.example.demo.config.auth.provider.GoogleUserInfo;
import com.example.demo.config.auth.provider.KakaoUserInfo;
import com.example.demo.config.auth.provider.NaverUserInfo;
import com.example.demo.config.auth.provider.OAuth2UserInfo;
import com.example.demo.domain.dtos.UserDto;
import com.example.demo.domain.entity.User;
import com.example.demo.domain.repository.UserRepository;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.util.Map;
import java.util.Optional;

@Service
@Slf4j
public class PrincipalDetailsOAuth2Service extends DefaultOAuth2UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        System.out.println("");
//        System.out.println("userRequest : "+userRequest);
//        System.out.println("userRequest.getClientRegistration() : "+userRequest.getClientRegistration());
//        System.out.println("userRequest.getAccessToken() : "+userRequest.getAccessToken());
//        System.out.println("userRequest.getAdditionalParameters() : "+userRequest.getAdditionalParameters());
//        System.out.println("userRequest.getAccessToken().getTokenValue() : "+userRequest.getAccessToken().getTokenValue()); //카카오 = 메세지 보낼때 토큰 사용
//        System.out.println("userRequest.getAccessToken().getTokenType().getValue() : "+userRequest.getAccessToken().getTokenType().getValue());
//        System.out.println("userRequest.getAccessToken().getScopes() : "+userRequest.getAccessToken().getScopes());
        System.out.println("");

        OAuth2User oAuth2User = super.loadUser(userRequest);
        System.out.println("oAuth2User : "+oAuth2User);
        System.out.println("oAuth2User.getAttributes() : "+oAuth2User.getAttributes());
        System.out.println("Provider Name : "+userRequest.getClientRegistration().getClientName()); //Kakao, Naver, Google

        String provider = userRequest.getClientRegistration().getClientName();
        Map<String, Object> attributes = oAuth2User.getAttributes();

        String username=null;
        OAuth2UserInfo oAuth2UserInfo = null;
        if(provider.startsWith("Kakao")){
            Long id = (Long)attributes.get("id");
            LocalDateTime connected_at=OffsetDateTime.parse(attributes.get("connected_at").toString()).toLocalDateTime();
            Map<String, Object> properties=(Map<String, Object>)attributes.get("properties");
            Map<String, Object> kakao_account=(Map<String, Object>)attributes.get("kakao_account");
            System.out.println("id : "+id);
            System.out.println("connected_at : "+connected_at);
            System.out.println("properties : "+properties);
            System.out.println("kakao_account : "+kakao_account);
            oAuth2UserInfo = KakaoUserInfo.builder()
                    .id(id)
                    .connected_at(connected_at)
                    .properties(properties)
                    .kakao_account(kakao_account)
                    .build();

            username=oAuth2UserInfo.getProvider()+"_"+oAuth2UserInfo.getProviderId();


        } else if(provider.startsWith("Naver")){
            Map<String, Object> response=(Map<String, Object>)attributes.get("response");
            System.out.println("response : "+response);
            oAuth2UserInfo = NaverUserInfo.builder()
                    .response(response)
                    .build();

            // DB 등록예정 계정명
            username=oAuth2UserInfo.getEmail();

        } else if(provider.startsWith("Google")){
            oAuth2UserInfo = GoogleUserInfo.builder()
                    .attributes(attributes)
                    .build();

            // DB 등록예정 계정명
            username=oAuth2UserInfo.getEmail();
        }
        System.out.println("oAuth2UserInfo : "+oAuth2UserInfo);

        // OAuth2 정보 -> 로컬계정생성 (계정x : 생성, 계정o : 불러오기)

        String password=passwordEncoder.encode("1234"); // 패스워드 암호화 : passwordEncoder

        // 기존 계정 존재 여부에 따라 DB저장
        Optional<User> userOptional=userRepository.findById(username);
        UserDto dto = null;
        if(userOptional.isEmpty()){ // user가 없다면 DB에 저장
            User user=new User();
            user.setUsername(username);
            user.setPassword(password);
            user.setRole("ROLE_USER");
            userRepository.save(user);

            dto=new UserDto(username,password,"ROLE_USER");
        } else{
            User user=userOptional.get();
            dto=new UserDto(username,user.getPassword(),user.getRole()); // password, role은 바뀔 수 있어서 DB로 부터 get 해줌.
        }

        // PrincipalDetails 로 변환해서 반환
        dto.setProvider(provider);
        dto.setProviderid(oAuth2UserInfo.getProviderId());
        return new PrincipalDetails(dto,oAuth2UserInfo.getAttributes()); // PrincipalDetails의 -> dto, attributes 전달
    }
}
