package com.springsecurity.security.service;


import com.springsecurity.security.model.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.function.Function;

@Service
public class JwtService {


    public String extractUsername( String token){
        return extractClaim(token , Claims::getSubject);
    }

    public boolean isValid(String token , UserDetails user){
        String username = extractUsername(token);
        return username.equals(user.getUsername()) && !isTokenExpired(token);
    }

    public boolean isTokenExpired (String token){
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token){
        return extractClaim(token , Claims::getExpiration);
    }
    public <T> T extractClaim(String token , Function<Claims,T> resolver){
        Claims claims = extractAllClaims(token);
        return resolver.apply(claims);
    }
    private Claims extractAllClaims(String token){
        return Jwts
                .parser()
                .verifyWith(getSignInKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
    public String generateToken (User user){
        String token;
        token = Jwts
                .builder()
                .subject(user.getUsername() )
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + 24*60*60*1000))
                .signWith(getSignInKey())
                .compact();
        return  token ;
    }

    private SecretKey getSignInKey(){
        String DECRYPTKEY = "7aeef453800de847e138be90a62375b8800792c28014784a68aa3ab134e1c5cb";
        byte[] keyBytes = Decoders.BASE64URL.decode(DECRYPTKEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
