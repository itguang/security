# Spring Security 初识（五）--spring security 和jwt整合

## 什么是 JWT

> json web token (JWT),是为了在网络环境中传递声明而设计的一种基于JSON的开放标准(RFC 7519),该token 被设计为紧凑且安全的.特别使用于分布式站点的登陆(SSO)
  场景.JWT一般被用来在服务提供者和服务认证者之间传递身份信息,以便可以从服务器获取资源.也可以增加一些额外的其它业务逻辑所必需的声明信息.
  该token可直接被用于认证,也可用于被加密.
  

### **基于token的鉴权机制**

基于token的鉴权机制也是类似于http协议无状态的,它不需要在服务段保留用户的认证信息或者鉴权信息.这就意味着基于token认证机制的用户就不必考虑在哪一台服务器登录了.
这就为应用的扩展提供了遍历.

认证流程:

![](imgs/1.png)

这个token必须在每次请求时传递给服务端,它应该保存在请求头里面.另外,服务器端要支持 CORS(跨来源资源共享策略) ,一般我们在服务器上这么做就可以了, `Access-Control-Allow-Origin: *`

### jwt的组成

![](imgs/2.png)

关于每个组成部分测详细说明可以参考这篇文章 :https://www.jianshu.com/p/576dbf44b2ae

jwt的三个组成部分共同构成了一个 签名信息 signature

**这个部分需要base64加密后的header和base64加密后的payload使用.连接组成的字符串.
然后通过header中声明的加密方式进行加盐secret组合加密，然后就构成了jwt的第三部分。** 

> 注意：secret是保存在服务器端的，jwt的签发生成也是在服务器端的，secret就是用来进行jwt的签发和jwt的验证，
  所以，它就是你服务端的私钥，在任何场景都不应该流露出去。一旦客户端得知这个secret, 那就意味着客户端是可以自我签发jwt了。


### 如何应用

一般是在请求头里加入Authorization，并加上Bearer标注：如下:

```js
fetch('api/user/1', {
  headers: {
    'Authorization': 'Bearer ' + token
  }
})
```

## Spring Security 结合 jwt

我们之前介绍过,Spring security是基于过滤器(Filter)的,使用过滤器我们可以很容易的拦截某些请求.
因此通过上面对jwt的了解,我们就可以在过滤器中处理token的生成和校验.

**大致流程如下:**

* 1.当用户进行提交登陆表单时,自定义一个拦截器JWTLoginFilter进行表单参数的获取.

* 2.验证提交的用户名密码是否正确.

* 3.如果登陆成功,使用jwt颁发一个token给客户端,之后的客户端请求都要带上这个token.

* 4.token验证:再自定义一个过滤器JWTAuthenticationFilter,当用户访问需要认证的请求时,拦截该请求,并进行token校验.

### Spring Security 安全相关配置类

我们为了简化开发使用spring boot进行项目的快速搭建.需要引入如下依赖:

```xml
<dependencies>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>

    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-test</artifactId>
        <scope>test</scope>
    </dependency>
</dependencies>
``` 

之后我们创建一个controller进行不同级别的验证.

```java
/**
 * @author itguang
 * @create 2018-01-02 10:29
 **/
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

```

接下来就是配置我们的安全管理类 SecurityConfig :

```java
/**
 * @author itguang
 * @create 2018-01-02 10:32
 **/
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
        auth.authenticationProvider(new CustomAuthenticationProvider(userDetailsService,bCryptPasswordEncoder));
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
                .addFilter(new JWTLoginFilter(authenticationManager()))
                //验证token
                .addFilter(new JWTAuthenticationFilter(authenticationManager()));
    }



}
```

可以看到我们的Security继承了 WebSecurityConfigurerAdapter ,关于WebSecurityConfigurerAdapter我们之前的文章已经介绍过,
我们重点关注的是重载的两个 configure() 方法.

**configure(HttpSecurity http):** 这个方法配置了对请求的拦截配置,在这里我们又添加了两个自定义的过滤器,JWTLoginFilter 和JWTAuthenticationFilter,
分别负责登录时用户名密码的验证,和拦截请求时对token的验证.

**configure(AuthenticationManagerBuilder auth):** 这个方法有点奇怪,我们并没有使用之前介绍几种的用户存储,而是使用了一个authenticationProvider()
方法,并传入了一个我们自定义的 AuthenticationProvider 类型的对象作为参数.稍后我们会详细介绍这个类到底是什么.


### 登陆信息 验证过滤器: JWTLoginFilter

```java

/**
 * @author itguang
 * @create 2018-01-02 13:48
 **/
public class JWTLoginFilter extends UsernamePasswordAuthenticationFilter {


    private AuthenticationManager authenticationManager;

    public JWTLoginFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }


    /**
     * 接收并解析用户登陆信息  /login,
     *为已验证的用户返回一个已填充的身份验证令牌，表示成功的身份验证
     *返回null，表明身份验证过程仍在进行中。在返回之前，实现应该执行完成该过程所需的任何额外工作。
     *如果身份验证过程失败，就抛出一个AuthenticationException
     *
     *
     * @param request  从中提取参数并执行身份验证
     * @param response 如果实现必须作为多级身份验证过程的一部分(比如OpenID)进行重定向，则可能需要响应
     * @return 身份验证的用户令牌，如果身份验证不完整，则为null。
     * @throws AuthenticationException
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {


        //得到用户登陆信息,并封装到 Authentication 中,供自定义用户组件使用.
        String username = request.getParameter("username");
        String password = request.getParameter("password");

        if (username == null) {
            username = "";
        }

        if (password == null) {
            password = "";
        }

        username = username.trim();


        ArrayList<GrantedAuthorityImpl> authorities = new ArrayList<>();

        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, password, authorities);

        //authenticate()接受一个token参数,返回一个完全经过身份验证的对象，包括证书.
        // 这里并没有对用户名密码进行验证,而是使用 AuthenticationProvider 提供的 authenticate 方法返回一个完全经过身份验证的对象，包括证书.
//        Authentication authenticate = authenticationManager.authenticate(authenticationToken);

//UsernamePasswordAuthenticationToken 是 Authentication 的实现类
        return authenticationToken;
    }


    /**
     * 登陆成功后,此方法会被调用,因此我们可以在次方法中生成token,并返回给客户端
     *
     * @param request
     * @param response
     * @param chain
     * @param authResult
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain, Authentication authResult) {

        String token = Jwts.builder()
                .setSubject(authResult.getName())
                //有效期两小时
                .setExpiration(new Date(System.currentTimeMillis() + 60 * 60 * 2 * 1000))
                //采用什么算法是可以自己选择的，不一定非要采用HS512
                .signWith(SignatureAlgorithm.HS512, "MyJwtSecret")
                .compact();

        response.addHeader("token", "Bearer " + token);

    }
}

```

我们可以看到 JWTLoginFilter 继承了 UsernamePasswordAuthenticationFilter,
并且重写了它的 attemptAuthentication() 方法和 successfulAuthentication() 方法.

在 attemptAuthentication()方法中,我们就可以得到 /login 提交的用户名和密码信息,但这里我们并没有返回一个认证后的 Authentication,
这是为什么呢?原因就在于,我们在 SecurityConfigure 的方法中,使用了一个自定义的 AuthenticationProvider 实现类,如:


 
```java
@Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {

       // auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder);
        // 使用自定义身份验证组件
        auth.authenticationProvider(new CustomAuthenticationProvider(userDetailsService,bCryptPasswordEncoder));
    }
```

那么 AuthenticationProvider 用来干嘛的呢? 查看他的源码可以发现:

```java

public interface AuthenticationProvider {
    
         /**
         * 验证登录信息,若登陆成功,设置 Authentication
         *
         * @param authentication
         * @return 一个完全经过身份验证的对象，包括凭证。
         *           如果AuthenticationProvider无法支持已通过的身份验证对象的身份验证，则可能返回null。
         *          在这种情况下，将会尝试支持下一个身份验证类的验证提供者。
         * @throws AuthenticationException
         */  
	
	Authentication authenticate(Authentication authentication)
			throws AuthenticationException;

	/**
         * 是否可以提供输入类型的认证服务
         *
         * 如果这个AuthenticationProvider支持指定的身份验证对象，那么返回true。
         * 返回true并不能保证身份验证提供者能够对身份验证类的实例进行身份验证。
         * 它只是表明它可以支持对它进行更深入的评估。身份验证提供者仍然可以从身份验证(身份验证)方法返回null，
         * 以表明应该尝试另一个身份验证提供者。在运行时管理器的运行时，可以选择具有执行身份验证的身份验证提供者。
         *
         * @param authentication
         * @return
         */
	boolean supports(Class<?> authentication);
}


```

### CustomAuthenticationProvider

AuthenticationProvider(身份验证提供者) 顾名思义,可以提供一个 Authentication 供Spring Security的上下文使用.

通过 supports 方法我们对特定的 Authentication进行认证,如果返回 true,就交给 authenticate(Authentication authentication) 方法,
此方法一个完全经过身份验证的对象，包括凭证。

如下我们自定义的 CustomAuthenticationProvider:

```java
/**
 * AuthenticationProvider(身份验证提供者) 顾名思义,可以提供一个 Authentication 供Spring Security的上下文使用,
 *
 * @author itguang
 * @create 2018-01-02 16:23
 **/
public class CustomAuthenticationProvider implements AuthenticationProvider {

    private UserDetailsService userDetailsService;

    private BCryptPasswordEncoder bCryptPasswordEncoder;

    public CustomAuthenticationProvider(UserDetailsService userDetailsService, BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.userDetailsService = userDetailsService;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }


    /**
     * 是否可以提供输入类型的认证服务
     * <p>
     * 如果这个AuthenticationProvider支持指定的身份验证对象，那么返回true。
     * 返回true并不能保证身份验证提供者能够对身份验证类的实例进行身份验证。
     * 它只是表明它可以支持对它进行更深入的评估。身份验证提供者仍然可以从身份验证(身份验证)方法返回null，
     * 以表明应该尝试另一个身份验证提供者。在运行时管理器的运行时，可以选择具有执行身份验证的身份验证提供者。
     *
     * @param authentication
     * @return
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }


    /**
     * 验证登录信息,若登陆成功,设置 Authentication
     *
     * @param authentication
     * @return 一个完全经过身份验证的对象，包括凭证。
     * 如果AuthenticationProvider无法支持已通过的身份验证对象的身份验证，则可能返回null。
     * 在这种情况下，将会尝试支持下一个身份验证类的验证提供者。
     * @throws AuthenticationException
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // 获取认证的用户名 & 密码
        String username = authentication.getName();
        String password = authentication.getCredentials().toString();

        //通过用户名从数据库中查询该用户
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);


        //判断密码(这里是md5加密方式)是否正确
        String dbPassword = userDetails.getPassword();
        String encoderPassword = DigestUtils.md5DigestAsHex(password.getBytes());

        if (!dbPassword.equals(encoderPassword)) {
            throw new UsernameIsExitedException("密码错误");
        }


        // 还可以从数据库中查出该用户所拥有的权限,设置到 authorities 中去,这里模拟数据库查询.
        ArrayList<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new GrantedAuthorityImpl("ADMIN"));

        Authentication auth = new UsernamePasswordAuthenticationToken(username, password, authorities);

        return auth;

    }


}

```

可见我们在这个 AuthenticationProvider 中对 UsernamePasswordAuthenticationToken 进行认证,

在 authenticate(Authentication authentication)方法中, authentication 就是 我们之前返回的 UsernamePasswordAuthenticationToken,我们可以得到登陆的用户名和密码,进行真正的认证.

如果认证成功 就给改 UsernamePasswordAuthenticationToken 设置对应的权限,最后把已经认证的 UsernamePasswordAuthenticationToken 返回即可.

还有我们在通过用户名从数据库查找用户时,返回了一个 UserDetails 对象,关于UserdDetails对象,我们之前的文章已经介绍过,不懂得可以去查看一下.

最后,当 CustomAuthenticationProvider 认证成功之后,JWTLoginFilter 中的 successfulAuthentication() 方法机会执行,因此我们就可以在这里设置token了,如下:

```java
/**
     * 登陆成功后,此方法会被调用,因此我们可以在次方法中生成token,并返回给客户端
     *
     * @param request
     * @param response
     * @param chain
     * @param authResult
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain, Authentication authResult) {

        String token = Jwts.builder()
                .setSubject(authResult.getName())
                //有效期两小时
                .setExpiration(new Date(System.currentTimeMillis() + 60 * 60 * 2 * 1000))
                //采用什么算法是可以自己选择的，不一定非要采用HS512
                .signWith(SignatureAlgorithm.HS512, "MyJwtSecret")
                .compact();

        response.addHeader("token", "Bearer " + token);

    }
```
我们使用JWT构造了一个token字符串,并把它放在了http请求头中返回给了客户端.

至此我们的登陆认证并返回 token就已经完成了,接下来就是客户端携带这已经获得token访问需要认证的资源时,我们需要对改token进行验证了.


### JWTAuthenticationFilter

```java
/**
 * token校验
 *
 * @author itguang
 * @create 2018-01-02 15:16
 **/
public class JWTAuthenticationFilter extends BasicAuthenticationFilter {

    public JWTAuthenticationFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }


    /**
     * 在此方法中检验客户端请求头中的token,
     * 如果存在并合法,就把token中的信息封装到 Authentication 类型的对象中,
     * 最后使用  SecurityContextHolder.getContext().setAuthentication(authentication); 改变或删除当前已经验证的 pricipal
     *
     * @param request
     * @param response
     * @param chain
     * @throws IOException
     * @throws ServletException
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {

        String token = request.getHeader("token");

        //判断是否有token
        if (token == null || !token.startsWith("Bearer ")) {
            chain.doFilter(request, response);
            return;
        }

        UsernamePasswordAuthenticationToken authenticationToken = getAuthentication(token);

        SecurityContextHolder.getContext().setAuthentication(authenticationToken);

        //放行
        chain.doFilter(request, response);


    }

    /**
     * 解析token中的信息,并判断是否过期
     */
    private UsernamePasswordAuthenticationToken getAuthentication(String token) {


        Claims claims = Jwts.parser().setSigningKey("MyJwtSecret")
                .parseClaimsJws(token.replace("Bearer ", ""))
                .getBody();

        //得到用户名
        String username = claims.getSubject();

        //得到过期时间
        Date expiration = claims.getExpiration();

        //判断是否过期
        Date now = new Date();

        if (now.getTime() > expiration.getTime()) {

            throw new UsernameIsExitedException("该账号已过期,请重新登陆");
        }


        if (username != null) {
            return new UsernamePasswordAuthenticationToken(username, null, new ArrayList<>());
        }
        return null;
    }


}
```

由此可以看到 JWTAuthenticationFilter 继承了 BasicAuthenticationFilter,

BasicAuthenticationFilter 用来处理一个HTTP请求的基本授权标头，将结果放入安全上下文。
总之，这个过滤器负责处理任何具有HTTP请求头的请求的请求，以及一个基本的身份验证方案和一个base64编码的用户名:密码令牌。
如果身份验证成功，那么最终的身份验证对象将被放入安全上下文。

因此我们就可以继承 BasicAuthenticationFilter 并重写 doFilterInternal()方法,在该方法中进行token的验证,如果验证成功,将结果放入安全上下文,如:
```java
 SecurityContextHolder.getContext().setAuthentication(authenticationToken);
```

## 大功告成

到此,我们就使用Spring Security + JWT ,搭建了一个安全的 resultful api ,接下来我们就进行简单的测试,这里我是用postman,这是一个非常好用的 http 调试工具.
我们现在数据库的users表中插入一条用户信息,用户名:itguang 密码: 123456,

接下来,打开post满,访问 localhost/login?username=itguang&password=123456

如下:

![](imgs/888.png)

 我们可以看到响应头中多了一个token
 ```properties
token →Bearer eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJpdGd1YW5nIiwiZXhwIjoxNTE0OTU2NjI3fQ.PIiH7dRrVgPc88kOPtGzvrqZf5l87FRe3h7s9YZVb2zkL_XwRc_v3uhn23bmKqu7G0pSZngdnX0rh_kT1YDwww
```
这就是我们使用jwt生成的token,现在是加密状态,接下来我们再访问 localhost/admin ,并把这个token放到 请求头中,如下:

![](imgs/99.png)

会看到返回了正确的字符串,但是如果我们不带该token值呢?

浏览器访问: http://localhost/admin ,会发现

![](imgs/3.png)

403,明显的没有权限禁止访问,这正是我们想要的结果.


## 小结

这节我们讲解了如何使用Spring Security 和jwt搭建安全的 restful api ,再结合前面我们对Spring Security的详细介绍,相信你已经对Spring Security的安全控制非常了解了.

除了Spring Security 我们还可以使用 shiro 进行安全控制,这同样是一个非常优秀的权限控制框架,有时间我也会带领大家一起研究下shiro.

































