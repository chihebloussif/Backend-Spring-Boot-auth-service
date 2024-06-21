package com.springsecurity.security.model;

import lombok.Getter;

@Getter
public class AuthenticationResponse {

    private final String token;
    private final UserDto user;

    public AuthenticationResponse(String token, UserDto user) {
        this.token = token;
        this.user = user;
    }

}
