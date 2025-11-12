package com.example.demo.config;

import com.example.demo.config.auth.exceptionHandler.CustomAccessDeniedHandler;
import com.example.demo.config.auth.exceptionHandler.CustomAuthenticationEntryPoint;
import com.example.demo.config.auth.jwt.JWTAuthorizationFilter;
import com.example.demo.config.auth.loginHandler.CustomFailureHandler;
import com.example.demo.config.auth.loginHandler.CustomSuccessHandler;
import com.example.demo.config.auth.logoutHandler.CustomLogoutHandler;
import com.example.demo.config.auth.logoutHandler.CustomLogoutSuccessHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig  {

    @Autowired
    CustomLogoutSuccessHandler customLogoutSuccessHandler;
    @Autowired
    CustomAccessDeniedHandler customAccessDeniedHandler;
    @Autowired
    CustomAuthenticationEntryPoint customAuthenticationEntryPoint;
    @Autowired
    CustomFailureHandler customFailureHandler;
    @Autowired
    CustomSuccessHandler customSuccessHandler;
    @Autowired
    CustomLogoutHandler customLogoutHandler;

    @Autowired
    JWTAuthorizationFilter jwtAuthorizationFilter;


    @Bean
    protected SecurityFilterChain configure(HttpSecurity http) throws Exception {


        //csrf 비활성화(비활성화하지 않으면 logout 요청은 기본적으로 POST방식을 따른다)
        http.csrf((config)->{config.disable();});

        //권한처리
        http.authorizeHttpRequests((auth)->{

            auth.requestMatchers("/","/join","/login").permitAll();

            auth.requestMatchers("/user").hasAnyRole("USER"); //
            auth.requestMatchers("/manager").hasAnyRole("MANAGER"); //
            auth.requestMatchers("/admin").hasAnyRole("ADMIN"); //

            auth.anyRequest().authenticated();

        });

        //로그인
        http.formLogin( (login)->{
            login.permitAll();
            login.loginPage("/login");
            login.successHandler(customSuccessHandler);     //로그인 성공시 동작하는 핸들러
            login.failureHandler(customFailureHandler);     //로그인 실패시(ID 미존재 , PW 불일치)
        });

        //로그아웃(설정시 POST처리)
        http.logout( (logout)->{
            logout.permitAll();
            logout.addLogoutHandler(customLogoutHandler);      //로그아웃 처리 핸들러
            logout.logoutSuccessHandler(customLogoutSuccessHandler);
        } );

        //예외처리
        http.exceptionHandling((ex)->{
            ex.authenticationEntryPoint(customAuthenticationEntryPoint);//미인증된 상태 + 권한이 필요한 Endpoint 접근시 예외처리
            ex.accessDeniedHandler(customAccessDeniedHandler); //인증이후 권한이 부족할때
        });
        
        //Oauth2-Client 활성화
        http.oauth2Login((oauth2)->{
            oauth2.loginPage("/login");

        });
        //SESSION 비활성화
        http.sessionManagement((sessionConfig)->{
            sessionConfig.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        });

        //TokenFilter 추가
        http.addFilterBefore(jwtAuthorizationFilter, LogoutFilter.class );

        //Etc..
        return http.build();
    }
    //임시계정생성
//    @Bean
//    UserDetailsService users() {
//        UserDetails user = User.withUsername("user")
//                .password("{noop}1234")   // 비밀번호 인코딩 없음 (실습용)
//                .roles("USER")            // ROLE_USER
//                .build();
//
//        UserDetails manager = User.withUsername("manager")
//                .password("{noop}1234")
//                .roles("MANAGER")         // ROLE_MANAGER
//                .build();
//
//        UserDetails admin = User.withUsername("admin")
//                .password("{noop}1234")
//                .roles("ADMIN")           // ROLE_ADMIN
//                .build();
//
//        return new InMemoryUserDetailsManager(user, manager, admin);
//    }

    // 패스워드 암호화작업(해시값생성)에 사용되는 Bean
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

}
