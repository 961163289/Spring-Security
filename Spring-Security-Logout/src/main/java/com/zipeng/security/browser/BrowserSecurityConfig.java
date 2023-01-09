package com.zipeng.security.browser;

import com.zipeng.handler.MyAuthenticationFailureHandler;
import com.zipeng.handler.MyAuthenticationSucessHandler;
import com.zipeng.handler.MyLogOutSuccessHandler;
import com.zipeng.session.MySessionExpiredStrategy;
import com.zipeng.validate.code.ValidateCodeFilter;
import com.zipeng.validate.smscode.SmsAuthenticationConfig;
import com.zipeng.validate.smscode.SmsCodeFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class BrowserSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private MyAuthenticationSucessHandler authenticationSucessHandler;
    @Autowired
    private MyAuthenticationFailureHandler authenticationFailureHandler;
    @Autowired
    private ValidateCodeFilter validateCodeFilter;
    @Autowired
    private SmsCodeFilter smsCodeFilter;
    @Autowired
    private SmsAuthenticationConfig smsAuthenticationConfig;
    @Autowired
    private MySessionExpiredStrategy sessionExpiredStrategy;
    @Autowired
    private MyLogOutSuccessHandler logOutSuccessHandler;


    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.addFilterBefore(validateCodeFilter, UsernamePasswordAuthenticationFilter.class) // 添加验证码校验过滤器
                .addFilterBefore(smsCodeFilter, UsernamePasswordAuthenticationFilter.class) // 添加短信验证码校验过滤器
                .formLogin() // 表单登录
                // http.httpBasic() // HTTP Basic
                .loginPage("/authentication/require") // 登录跳转 URL
                .loginProcessingUrl("/login") // 处理表单登录 URL
                .successHandler(authenticationSucessHandler) // 处理登录成功
                .failureHandler(authenticationFailureHandler) // 处理登录失败
                .and()
                .authorizeRequests() // 授权配置
                .antMatchers("/authentication/require",
                        "/login.html",
                        "/code/image",
                        "/code/sms",
                        "/session/invalid",
                        "/signout/success").permitAll() // 无需认证的请求路径
                .anyRequest()  // 所有请求
                .authenticated() // 都需要认证
                .and()
                .sessionManagement() // 添加 Session 管理器
                .invalidSessionUrl("/session/invalid") // Session 失效后跳转到这个链接
                .maximumSessions(1) // 配置最大Session并发数量为1个
                .maxSessionsPreventsLogin(true) // 控制当 Session 达到最大有效数的时候,不再允许相同的账户登陆
                .expiredSessionStrategy(sessionExpiredStrategy) // 配置 Session 在并发失效后的处理策略
                .and()
                .and()
                .logout()
                .logoutUrl("/signout")
                //.logoutSuccessUrl("/signout/success")
                .logoutSuccessHandler(logOutSuccessHandler)
                .deleteCookies("JSESSIONID")
                .and()
                .csrf().disable()
                .apply(smsAuthenticationConfig); // 将短信验证码认证配置加到 Spring Security 中
    }

}
