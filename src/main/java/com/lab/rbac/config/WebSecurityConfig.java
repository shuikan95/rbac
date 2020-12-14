package com.lab.rbac.config;

import com.lab.rbac.provider.MyAuthenticationProvider;
import com.lab.rbac.service.MyUserDetailsService;
import com.lab.rbac.utils.R;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.*;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.io.PrintWriter;
import java.util.Arrays;

@Configuration
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/vc.jpg").permitAll()
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .loginProcessingUrl("/login").usernameParameter("username").passwordParameter("password")
                .successHandler((req, resp, authentication) -> {
                    Object principal = authentication.getPrincipal();
                    resp.setContentType("application/json;charset=utf-8");
                    PrintWriter out = resp.getWriter();
                    out.write(R.error(getUsername() + " 登录成功！").toString());
                    out.flush();
                    out.close();
                })
                .failureHandler((req, resp, e) -> {
                    resp.setContentType("application/json;charset=utf-8");
                    PrintWriter out = resp.getWriter();
                    R r = R.error();
                    if (e instanceof LockedException) {
                        r.put("msg", "账户被锁定，请联系管理员!");
                    } else if (e instanceof CredentialsExpiredException) {
                        r.put("msg", "密码过期，请联系管理员!");
                    } else if (e instanceof AccountExpiredException) {
                        r.put("msg", "账户过期，请联系管理员!");
                    } else if (e instanceof DisabledException) {
                        r.put("msg", "账户被禁用，请联系管理员!");
                    } else if (e instanceof BadCredentialsException) {
                        r.put("msg", "用户名或者密码输入错误，请重新输入!");
                    } else {
                        r.put("msg", e.getMessage());
                    }
                    out.write(r.toString());
                    out.flush();
                    out.close();
                })
                .permitAll()
                .and()
                .logout()
                .logoutUrl("/logout")
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
                .deleteCookies()
                .clearAuthentication(true)
                .invalidateHttpSession(true)
                .logoutSuccessHandler((req, resp, authentication) -> {
                    resp.setContentType("application/json;charset=utf-8");
                    PrintWriter out = resp.getWriter();
                    out.write(R.error("注销成功").toString());
                    out.flush();
                    out.close();
                })
                .permitAll()
                .and()
                .csrf().disable().exceptionHandling()
                .authenticationEntryPoint((req, resp, authException) -> {
                            resp.setContentType("application/json;charset=utf-8");
                            PrintWriter out = resp.getWriter();
                            out.write(R.error("尚未登录，请先登录").toString());
                            out.flush();
                            out.close();
                        }
                );

    }

    private String getUsername() {
        String username = null;
        //当前认证通过的用户身份
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        //用户身份
        Object principal = authentication.getPrincipal();
        if (principal == null) {
            username = "匿名";
        }
        if (principal instanceof org.springframework.security.core.userdetails.UserDetails) {
            UserDetails userDetails = (UserDetails) principal;
            username = userDetails.getUsername();
        } else {
            username = principal.toString();
        }
        return username;
    }

    @Autowired
    private MyUserDetailsService userDetailsService;

    @Bean
    RoleHierarchy roleHierarchy() {
        RoleHierarchyImpl hierarchy = new RoleHierarchyImpl();
        hierarchy.setHierarchy("ROLE_admin > ROLE_user");
        return hierarchy;
    }


    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(10);
    }

    @Bean
    MyAuthenticationProvider myAuthenticationProvider() {
        MyAuthenticationProvider myAuthenticationProvider = new MyAuthenticationProvider();
        myAuthenticationProvider.setPasswordEncoder(passwordEncoder());
        myAuthenticationProvider.setUserDetailsService(userDetailsService);
        return myAuthenticationProvider;
    }

    @Override
    @Bean
    protected AuthenticationManager authenticationManager() throws Exception {
        ProviderManager manager = new ProviderManager(Arrays.asList(myAuthenticationProvider()));
        return manager;
    }
}
