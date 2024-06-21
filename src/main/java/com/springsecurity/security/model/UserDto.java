package com.springsecurity.security.model;


import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UserDto {

    private String username;
    private Role role;

    public UserDto(String username, Role role) {
        this.username = username;
        this.role = role;
    }
}
