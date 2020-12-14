package com.lab.rbac.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
public class HelloController {

    @RequestMapping(value = "/hello", method = {RequestMethod.GET, RequestMethod.POST})
    public String hello() {
        return "hello...";
    }

    @GetMapping("/r/r1")
    @PreAuthorize("hasAuthority('p1')")//拥有p1权限才可以访问
    public String r1() {
        return "访问资源1";
    }

    @GetMapping("/r/r2")
    @PreAuthorize("hasAuthority('p3')")//拥有p2权限才可以访问
    public String r2() {
        return "访问资源2";
    }
}