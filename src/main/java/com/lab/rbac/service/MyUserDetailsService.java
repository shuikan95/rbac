package com.lab.rbac.service;

import com.lab.rbac.entity.User;
import com.lab.rbac.dao.UserDao;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class MyUserDetailsService implements UserDetailsService {

    @Autowired
    private UserDao userDao;

    //根据 账号查询用户信息
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        //将来连接数据库根据账号查询用户信息
        User user = userDao.getUserByUsername(username);
        if(user == null){
            //如果用户查不到，返回null，由provider来抛出异常
            return null;
        }
        //根据用户的id查询用户的权限
        List<String> permissions = userDao.findPermissionsByUserId(user.getId());
        //将permissions转成数组
        String[] permissionArray = new String[permissions.size()];
        permissions.toArray(permissionArray);
        UserDetails userDetails = org.springframework.security.core.userdetails.User.withUsername(user.getUsername()).password(user.getPassword()).authorities(permissionArray).build();
        return userDetails;
    }
}
