package com.itguang.springsecurityjwt2.web;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {




    @RequestMapping("/hello")
    public String hello(){

        return "hello";
    }

    @RequestMapping("/userList")
    public String userList(){

        return "userList";
    }

    @RequestMapping("/admin")
    public String admin(){

        return "admin";
    }



}

