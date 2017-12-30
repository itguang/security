package com.itguang.springsecuritydemo5.service;

import org.springframework.security.access.annotation.Secured;
import org.springframework.stereotype.Service;

/**
 * @author itguang
 * @create 2017-12-30 11:07
 **/
@Service
public class UserService {

    @Secured("ROLE_USER")
    public void addUser(){

    }

}
