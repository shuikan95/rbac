package com.lab.rbac.entity;

import lombok.Data;

@Data
public class User {
    private String id;
    private String username;
    private String password;
    private String fullname;
    private String mobile;
}
