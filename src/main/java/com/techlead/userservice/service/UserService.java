package com.techlead.userservice.service;

import com.techlead.userservice.model.Role;
import com.techlead.userservice.model.User;

import java.util.List;

public interface UserService {


    User saveUser(User user);
    Role saveRole(Role role);
    void addRoleToUser(String username, String roleName);
    User getUser(String username);
    List<User> getUsers();

}
