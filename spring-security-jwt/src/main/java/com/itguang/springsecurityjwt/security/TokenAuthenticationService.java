package com.itguang.springsecurityjwt.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import javax.servlet.http.HttpServletResponse;
import java.util.Date;

/**
 * JWT生成，和验签
 * @author itguang
 * @create 2018-01-02 11:09
 **/
public class TokenAuthenticationService {

    static final long EXPIRATIONTIME = 432_000_000;     // 5天
    static final String SECRET = "P@ssw02d";            // JWT密码
    static final String TOKEN_PREFIX = "Bearer";        // Token前缀
    static final String HEADER_STRING = "Authorization";// 存放Token的Header Key


    /**
     * JWT 的生成token的方法
     */

    public static void addAuthentication(HttpServletResponse response, String username){

        //生成 jwt

        String token = Jwts.builder()
                .claim("authorities", "ROLE_ADMIN,AUTH_WRITE")
                .setSubject(username)
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATIONTIME))
                .signWith(SignatureAlgorithm.ES512, SECRET)
                .compact();

        //把token设置到响应头中去
        response.addHeader("Authorization", "Bearer " + token);

    }


}
