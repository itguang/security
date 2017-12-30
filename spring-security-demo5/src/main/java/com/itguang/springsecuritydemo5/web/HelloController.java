package com.itguang.springsecuritydemo5.web;

import com.itguang.springsecuritydemo5.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.security.RolesAllowed;

/**
 * @author itguang
 * @create 2017-12-28 9:44
 **/
@RestController
public class HelloController {


    @Autowired
    private UserService userService;


    @RequestMapping("/hello")
    @Secured({"ROLE_ADMIN","ROLE_USER"})
    public String hello() {

        return "hello Spring Security";

    }


    @RequestMapping("/admin")
    @Secured("ROLE_ADMIN")
    public String admin(){
        return "admin";
    }

    @RequestMapping("/test1")
    @RolesAllowed("ROLE_ADMIN")
    public String test1(){
        return "test1";
    }






}
