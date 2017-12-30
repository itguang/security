package com.itguang.springsecurotydemo3.service;

import com.itguang.springsecurotydemo3.entity.UserEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.ArrayList;

/**
 * 自定义用户实现
 *
 * @author itguang
 * @create 2017-12-29 8:23
 **/
public class MyUserService implements UserDetailsService {


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {



        //自定义用户存储数据来源，可以是从关系型数据库，非关系性数据库，或者其他地方获取用户数据。
        UserEntity userEntity = new UserEntity("itguang", "123456", true);

        //还可以在此设置账号的锁定,过期,凭据失效 等参数
        //...

        // 设置 权限,可以是从数据库中查找出来的
        ArrayList<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
        authorities.add(new SimpleGrantedAuthority("ROLE_ADMIN"));


        userEntity.setAuthorities(authorities);

        return userEntity;
    }
}
