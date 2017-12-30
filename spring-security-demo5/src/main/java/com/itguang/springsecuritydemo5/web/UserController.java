package com.itguang.springsecuritydemo5.web;


import com.itguang.springsecuritydemo5.entity.UserEntity;
import org.apache.catalina.User;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.prepost.PreFilter;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;

/**
 * @author itguang
 * @create 2017-12-30 11:04
 **/
@RestController
public class UserController {


    @RequestMapping("/addUser")

    @PreAuthorize("hasRole('ROLE_USER') and #userEntity.password>8 or hasRole('ROLE_ADMIN')")
    public String addUser(UserEntity userEntity) {
        return "addUser ok";
    }

    @RequestMapping("/getUser/{username}")
    @PostAuthorize("returnObject.username == principal.username")
    public UserEntity getUser(@PathVariable(value = "username") String username) {

        //模拟从数据库中查找
        UserEntity userEntity = new UserEntity(username);

        return userEntity;
    }


    @RequestMapping("getAll")
    @PreAuthorize("hasRole('ROLE_USER')")
    @PostFilter("filterObject.enabled == true")
    public List<UserEntity> getAllUser(){

        ArrayList<UserEntity> list = new ArrayList<>();
        list.add(new UserEntity("test1","123456",true));
        list.add(new UserEntity("test1","123456",false));

        return list;
    }

    @RequestMapping("/delete")
    @PreAuthorize("ROLE_USER")
    @PreFilter("hasPermission(targetObject,'delete')")
    public String getAllUser(List<UserEntity> list){


        return "ok";
    }




}
