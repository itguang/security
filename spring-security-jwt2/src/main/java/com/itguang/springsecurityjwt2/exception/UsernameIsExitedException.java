package com.itguang.springsecurityjwt2.exception;

import org.springframework.security.core.AuthenticationException;

/**
 * @author zhaoxinguo on 2017/9/13.
 */
public class UsernameIsExitedException extends AuthenticationException {

    public UsernameIsExitedException(String msg) {
        super(msg);
    }

    public UsernameIsExitedException(String msg, Throwable t) {
        super(msg, t);
    }
}