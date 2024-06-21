package com.springsecurity.security.service;


import com.springsecurity.security.model.AuthenticationResponse;
import com.springsecurity.security.model.User;
import com.springsecurity.security.model.UserDto;
import com.springsecurity.security.repository.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class AuthenticationService {

    private final UserRepository userRepository ;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;

    public AuthenticationService(UserRepository userRepository, PasswordEncoder passwordEncoder,  AuthenticationManager authenticationManager, JwtService jwtService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
    }

    public boolean isUserExists(String username) {
        // Check if user already exists in the database
        Optional<User> existingUser = userRepository.findByUsername(username);
        return existingUser.isPresent();
    }

    public AuthenticationResponse register(User request) {
        User user = new User();
        user.setFirstName(request.getFirstName());
        user.setLastName(request.getLastName());
        user.setUsername(request.getUsername());
        user.setPassword(passwordEncoder.encode(request.getPassword()));

        user.setRole(request.getRole());
        if (isUserExists(user.getUsername())) {
            // Throw an exception or handle the case where the user already exists

          throw new RuntimeException("User already exists") ;
        }
        user = userRepository.save(user);

        String token = jwtService.generateToken(user);

        UserDto userDTO = new UserDto(user.getUsername(), user.getRole());
        return new AuthenticationResponse(token, userDTO);
    }

    public AuthenticationResponse authenticate(User request){
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                )
        );
        User user = userRepository.findByUsername(request.getUsername()).orElseThrow();
        UserDto userDto = new UserDto(user.getUsername(), user.getRole());
        String token = jwtService.generateToken(user);
        return new AuthenticationResponse(token,userDto);
    }
}
