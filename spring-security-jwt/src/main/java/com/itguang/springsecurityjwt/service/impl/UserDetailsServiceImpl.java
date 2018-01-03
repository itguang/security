package com.itguang.springsecurityjwt.service.impl;

import com.itguang.springsecurityjwt.entity.User;
import com.itguang.springsecurityjwt.exception.UsernameIsExitedException;
import com.itguang.springsecurityjwt.repository.UserRepository;
import com.itguang.springsecurityjwt.security.GrantedAuthorityImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

import static java.util.Collections.emptyList;

/**
 * @author itguang
 * @create 2018-01-02 16:07
 **/

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username);
        if (user == null) {
            throw new UsernameIsExitedException("该用户不存在");
        }


        // 关于 UserDetailsService 和 User 对象之前的文章已经讲过.
        return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(), emptyList());


    }
}
