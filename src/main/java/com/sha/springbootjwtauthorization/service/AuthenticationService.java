package com.sha.springbootjwtauthorization.service;

import com.sha.springbootjwtauthorization.model.User;

public interface AuthenticationService {
    User signInAndReturnJWT(User signInRequest);
}
