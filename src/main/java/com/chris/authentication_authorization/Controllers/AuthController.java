package com.chris.authentication_authorization.Controllers;

import com.chris.authentication_authorization.Models.UserEntity;
import com.chris.authentication_authorization.Services.AuthService;
import com.chris.authentication_authorization.Services.CustomUserDetailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {
    @Autowired
    private final AuthService authService;

    public AuthController(AuthService authService){
        this.authService = authService;
    }

    // Register User
    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody UserEntity user){
        return ResponseEntity.ok(authService.registerUser(user));
    }

    //Login User
    @PostMapping("/login")
    public Map<String, Object> loginUser(@RequestParam String username, @RequestParam String password){
        return authService.loginUser(username, password);
    }
}
