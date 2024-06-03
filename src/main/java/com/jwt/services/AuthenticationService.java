package com.jwt.services;

import com.jwt.dto.JwtAuthenticationResponse;
import com.jwt.dto.RefreshTokenRequest;
import com.jwt.dto.SignInRequest;
import com.jwt.dto.SignUpRequest;
import com.jwt.entity.User;

public interface AuthenticationService {

    public User signUp(SignUpRequest signUpRequest);

    public JwtAuthenticationResponse signIn(SignInRequest signInRequest);
    public JwtAuthenticationResponse refreshToken(RefreshTokenRequest refreshTokenRequest);

}
