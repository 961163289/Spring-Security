package com.zipeng.security.browser;

import com.zipeng.handler.MyAuthenticationFailureHandler;
import com.zipeng.handler.MyAuthenticationSucessHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class BrowserSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private MyAuthenticationSucessHandler authenticationSucessHandler;
    @Autowired
    private MyAuthenticationFailureHandler authenticationFailureHandler;

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.formLogin() // 表单登陆
                .loginPage("/authentication/require") // 登陆跳转 URL
                .loginProcessingUrl("/login") // 处理表单登陆 URL
                .successHandler(authenticationSucessHandler) // 处理登陆成功
                .failureHandler(authenticationFailureHandler) // 处理登陆失败
                .and()
                .authorizeRequests() // 授权配置
                .antMatchers("/authentication/require", "/login.html").permitAll() // 登陆跳转 URL 无需认证
                .anyRequest() // 所有请求
                .authenticated() // 都需要认证
                .and()
                .csrf()
                .disable();
    }

}
