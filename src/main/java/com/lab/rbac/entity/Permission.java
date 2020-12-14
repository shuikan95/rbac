package com.lab.rbac.entity;

import lombok.Data;

@Data
public class Permission {
    private String id;
    private String code;
    private String description;
    private String url;
}
