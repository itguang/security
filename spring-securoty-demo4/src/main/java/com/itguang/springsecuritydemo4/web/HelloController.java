package com.itguang.springsecuritydemo4.web;

import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author itguang
 * @create 2017-12-28 9:44
 **/
@RestController
@RequestMapping("/shop")
public class HelloController {

    @RequestMapping("/hello")
    public String hello() {



        return "hello Spring Security";
    }

    @RequestMapping("/index")
    public String index() {
        return "index";
    }

    @RequestMapping("/order")
    public String order() {
        return "order";
    }

    @RequestMapping("/order/paid")
    public String paid(){
        return "paid";
    }


}
