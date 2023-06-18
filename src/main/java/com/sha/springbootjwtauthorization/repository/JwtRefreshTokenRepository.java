package com.sha.springbootjwtauthorization.repository;

import com.sha.springbootjwtauthorization.model.JwtRefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;

public interface JwtRefreshTokenRepository  extends JpaRepository<JwtRefreshToken,String> {
}
