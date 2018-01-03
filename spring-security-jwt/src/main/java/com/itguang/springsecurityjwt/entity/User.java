package com.itguang.springsecurityjwt.entity;


import lombok.Data;

import javax.persistence.*;

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