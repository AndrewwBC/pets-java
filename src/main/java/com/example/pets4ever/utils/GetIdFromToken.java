package com.example.pets4ever.utils;


import com.example.pets4ever.infra.security.TokenService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class GetIdFromToken {

    @Autowired
    TokenService tokenService;
    public String id(String token) {
        String jwt = token.replace("Bearer ", "");
        System.out.println(jwt);
        return tokenService.validateTokenAndGetUserId(jwt);
    }
}
