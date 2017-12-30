package com.itguang.springsecuritydemo5.entity;

import lombok.Data;

/**
 * @author itguang
 * @create 2017-12-30 14:39
 **/
@Data
public class UserEntity {


    private String username;

    private String password;

    private String email;

    private Integer age;

    private Boolean enabled;

    public UserEntity(String username) {
        this.username = username;
    }

    public UserEntity(String username, String password, Boolean enabled) {
        this.username = username;
        this.password = password;
        this.enabled = enabled;
    }
}
