package com.springsecurity.security.controller;


import com.springsecurity.security.model.AuthenticationResponse;
import com.springsecurity.security.model.User;
import com.springsecurity.security.service.AuthenticationService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthenticationController {

      private final AuthenticationService authenticationService;


    public AuthenticationController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    @CrossOrigin(origins = "http://localhost:5173")
    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(
            @RequestBody User request
            ) {
        
        return ResponseEntity.ok(authenticationService.register(request));
    }

    @CrossOrigin(origins = "http://localhost:5173")
    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> login (
            @RequestBody User request
    ) {
        return ResponseEntity.ok(authenticationService.authenticate(request));
    }
}
