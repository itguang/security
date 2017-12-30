package com.itguang.springsecuritydemo4.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 * @author itguang
 * @create 2017-12-28 9:19
 **/
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    /**
     * 基于内存的用户存储
     * @param auth
     * @throws Exception
     */
    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("itguang").password("123456").roles("USER").and()
                .withUser("admin").password("123456").roles("ADMIN");
    }

    /**
     * 请求拦截
     * @param http
     * @throws Exception
     */
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http.authorizeRequests()
//                .antMatchers("/hello").authenticated()
//                .antMatchers(HttpMethod.POST,"/order").authenticated()
//                .anyRequest().permitAll();
//    }

    /**
     * 请求拦截
     * @param http
     * @throws Exception
     */
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http.authorizeRequests()
//                .antMatchers("/hello").hasAnyAuthority("ROLE_DELETE")
//                .antMatchers(HttpMethod.POST,"/order").hasAnyAuthority("ROLE_UPDATE")
//                .anyRequest().permitAll();
//    }

    /**
     * 请求拦截
     * @param http
     * @throws Exception
     */
    //@Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http.authorizeRequests()
//                .antMatchers("/hello").hasRole("USER")
//                .antMatchers(HttpMethod.POST,"/order").hasRole("UPDATE")
//                .anyRequest().permitAll()
//                .and()
//                .formLogin().and()
//                .httpBasic();
//    }






}
