package com.itguang.springsecurotydemo3.web;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author itguang
 * @create 2017-12-28 9:44
 **/
@RestController
public class HelloController {

    @RequestMapping("hello")
    public String hello() {

        return "hello Spring Security";
    }
}
