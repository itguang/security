package com.itguang.springsecurityjwt.web;

import com.itguang.springsecurityjwt.entity.User;
import com.itguang.springsecurityjwt.exception.UsernameIsExitedException;
import com.itguang.springsecurityjwt.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.util.DigestUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
public class UserController {

    @Autowired
    private UserRepository applicationUserRepository;


    @RequestMapping("/hello")
    public String hello(){

        return "hello";
    }

    @RequestMapping("/userList")
    public Map<String, Object> userList(){
        List<User> myUsers = applicationUserRepository.findAll();
        Map<String, Object> map = new HashMap<String, Object>();
        map.put("users",myUsers);
        return map;
    }

    @RequestMapping("/admin")
    public String admin(){

        return "admin";
    }



}

