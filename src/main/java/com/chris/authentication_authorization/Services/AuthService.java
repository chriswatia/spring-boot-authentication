package com.chris.authentication_authorization.Services;

import com.chris.authentication_authorization.Models.UserEntity;
import com.chris.authentication_authorization.Repositories.AuthRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

@Service
public class AuthService {
    @Autowired
    private final AuthRepository authRepository;
    @Autowired
    private JwtEncoder jwtEncoder;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private AuthenticationManager authenticationManager;
    // Constructor
    public AuthService(AuthRepository authRepository) {
        this.authRepository = authRepository;
    }

    // Register User
    public String registerUser(UserEntity user){
        // Check if user already exists
        Optional<UserEntity> userEntity = authRepository.findByUsername(user.getUsername());

        if(userEntity.isPresent()){
            return "Username already taken";
        }

        // Encode Password
        user.setPassword(passwordEncoder.encode(user.getPassword()));

        //Set Role
        user.setRole("ROLE_USER");

        //Save User
        authRepository.save(user);

        return "User Registered Successfully";
    }

    // Login User
    public Map<String, Object> loginUser(String username, String password){
        Map<String, Object> response = new HashMap<>();
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));

        // Check if user exists
        Optional<UserEntity> userEntity = authRepository.findByUsername(username);
        if(!userEntity.isPresent()){
            response.put("message", "User not found");
            return response;
        }

        String accessToken = generateToken(userEntity.get(), authentication, 3600);
        response.put("access_token", accessToken);
        response.put("message", "Login Successful");
        response.put("expires_in", 3600);

        return response;
    }

    // Generate Access Token
    private String generateToken(UserEntity userEntity, Authentication authentication, long expiryDuration){
        Instant now = Instant.now();

        JwtClaimsSet claimsSet = JwtClaimsSet.builder()
                .issuer("http://localhost:8080")
                .issuedAt(now)
                .expiresAt(now.plusSeconds(expiryDuration))
                .subject(userEntity.getUsername())
                .claim("role", authentication.getAuthorities().toString())
                .claim("firstName", userEntity.getFirstname())
                .build();

        return jwtEncoder.encode(JwtEncoderParameters.from(claimsSet)).getTokenValue();
    }

}
