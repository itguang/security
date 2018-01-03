package com.itguang.springsecurityjwt.security;

import org.springframework.security.core.GrantedAuthority;

/**
 * @author itguang
 * @create 2018-01-02 11:08
 **/
public class GrantedAuthorityImpl implements GrantedAuthority {
    private String authority;

    public GrantedAuthorityImpl(String authority) {
        this.authority = authority;
    }

    public void setAuthority(String authority) {
        this.authority = authority;
    }

    @Override
    public String getAuthority() {
        return this.authority;
    }
}
