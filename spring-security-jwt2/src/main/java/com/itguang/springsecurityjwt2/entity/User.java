package com.itguang.springsecurityjwt2.entity;


import lombok.Data;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Table;

/**
 * @author zhaoxinguo on 2017/9/13.
 */
@Entity
@Table(name = "users")
@Data
public class User {

    @Id
    @GeneratedValue
    private long id;

    private String username;

    private String password;

    private Boolean enabled;

    private String email;

}