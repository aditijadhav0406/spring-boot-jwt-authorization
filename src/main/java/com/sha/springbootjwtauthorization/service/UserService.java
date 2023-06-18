package com.sha.springbootjwtauthorization.service;

import com.sha.springbootjwtauthorization.model.Role;
import com.sha.springbootjwtauthorization.model.User;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;


public interface UserService {
    User saveUser(User user);

    Optional<User> findByUsername(String username);

    abstract void changeRole(Role newRole, String username);

    List<User> findAllUsers();
}
