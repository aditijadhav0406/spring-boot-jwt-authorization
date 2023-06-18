package com.sha.springbootjwtauthorization.service;

import com.sha.springbootjwtauthorization.model.JwtRefreshToken;
import com.sha.springbootjwtauthorization.model.User;

public interface JwtRefreshTokenService {

    JwtRefreshToken createRefreshToken(Long userId);
    User generateAccessTokenFromRefreshToken(String refreshTokenId);
}
