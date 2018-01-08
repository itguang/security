# 一个完美的 基于 Spring Security 和JWT 的安全拦截以及权限验证demo


## SecurityConfig配置如下:

```java
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    private UserDetailsServiceImpl userDetailsService;


    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {

        // auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder);
        // 使用自定义身份验证组件
        auth.authenticationProvider(new CustomAuthenticationProvider(userDetailsService, bCryptPasswordEncoder));
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //禁用 csrf
        http.cors().and().csrf().disable().authorizeRequests()
                //允许以下请求
                .antMatchers("/hello").permitAll()
                // 所有请求需要身份认证
                .anyRequest().authenticated()
                .and()
                //验证登陆
                .addFilterBefore(new JWTLoginFilter("/login", authenticationManager()), UsernamePasswordAuthenticationFilter.class)
                //验证token
                .addFilterBefore(new JWTAuthenticationFilter(authenticationManager()), UsernamePasswordAuthenticationFilter.class);
    }


}
```

重点在于这两个

```java
//验证登陆
.addFilterBefore(new JWTLoginFilter("/login", authenticationManager()), UsernamePasswordAuthenticationFilter.class)
//验证token
.addFilterBefore(new JWTAuthenticationFilter(authenticationManager()), UsernamePasswordAuthenticationFilter.class);
```

**需要注意的是,Spring Security 的登陆url不是一个controller,而是一个拦截器,给一个登陆拦截器传一个拦截的url,比如 /login 就可以拦截这个请求.**




# 一个Spring Security 结合 jwt 生成和校验的工具类

```java
package com.yearcon.pointshop.common.config.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Date;
import java.util.List;

/**
 * token 验证工具类
 *
 * @author itguang
 * @create 2018-01-06 15:01
 **/
public class TokenAuthenticationService {

    /**
     * 过期时间 2小时
     */
    static final long EXPIRATIONTIME = 1000 * 60 * 60 * 2;
    /**
     * JWT 密码
     */
    static final String SECRET = "www.yearcon.cn";
    /**
     * TOKEN前缀
     */
    static final String TOKEN_PREFIX = "Bearer ";
    /**
     * 存放Token的Header Key
     */
    static final String HEADER_STRING = "token";

    /**
     * 自定义的 playload
     */
    static final String AUTHORITIES = "authorities";

    /**
     * 将jwt token 写入header头部
     *
     * @param response
     * @param authResult
     */
    public static void addAuthenticatiotoHttpHeader(HttpServletResponse response, Authentication authResult) {

        //得到以 , 分割的权限字符串
        String auth= authResult.getAuthorities().toString();
        //得到 权限 列表
        //List<? extends GrantedAuthority> authorities = (List<? extends GrantedAuthority>) authResult.getAuthorities();


        //生成 jwt
        String token = Jwts.builder()
                //生成token的时候可以把自定义数据加进去,比如用户权限,注意这里之所以不存对象,是为了减少颁发给客户端token的长度.
                .claim(AUTHORITIES, auth)
                .setSubject(authResult.getName())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATIONTIME))
                .signWith(SignatureAlgorithm.HS512, SECRET)
                .compact();

        //把token设置到响应头中去
        response.addHeader(HEADER_STRING, TOKEN_PREFIX + token);

    }

    /**
     * 从请求头中解析出 Authentication
     * @param request
     * @return
     */
    public static Authentication getAuthentication(HttpServletRequest request) {
        // 从Header中拿到token
        String token = request.getHeader(HEADER_STRING);
        if(token==null){
            return null;

        }


        Claims claims = Jwts.parser().setSigningKey(SECRET)
                .parseClaimsJws(token.replace(TOKEN_PREFIX, ""))
                .getBody();

        String auth = (String)claims.get(AUTHORITIES);

        // 得到 权限（角色）
        List<GrantedAuthority> authorities =  AuthorityUtils.
                commaSeparatedStringToAuthorityList((String) claims.get(AUTHORITIES));

        //得到用户名
        String username = claims.getSubject();

        //得到过期时间
        Date expiration = claims.getExpiration();

        //判断是否过期
        Date now = new Date();

        if (now.getTime() > expiration.getTime()) {

            throw new CredentialsExpiredException("该账号已过期,请重新登陆");
        }


        if (username != null) {
            return new UsernamePasswordAuthenticationToken(username, null, authorities);
        }
        return null;

    }
}

```



















