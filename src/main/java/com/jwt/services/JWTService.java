package com.jwt.services;

import org.springframework.security.core.userdetails.UserDetails;

import java.util.HashMap;

public interface JWTService {

    String generateToken(UserDetails userDetails);

    String getUserNameFromToken(String token);

    Boolean isTokenValid(String token, UserDetails userDetails);

    String generateRefreshToken(HashMap<String, Object> extractClaims, UserDetails userDetails);
}
