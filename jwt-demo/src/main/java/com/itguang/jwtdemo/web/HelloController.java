package com.itguang.jwtdemo.web;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author itguang
 * @create 2017-12-27 15:53
 **/
@RestController
public class HelloController {










    @RequestMapping
    public String hello(){

        return "hello";
    }

}
