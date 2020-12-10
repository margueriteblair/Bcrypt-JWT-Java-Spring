package com.encryption.cd;


import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.security.crypto.bcrypt.BCrypt;

import javax.crypto.SecretKey;
import java.security.Key;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.HashMap;

//MORE ON JWT PACKAGE USED HERE; https://github.com/jwtk/jjwt
//BCRYPT DOCS: https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/crypto/bcrypt/BCrypt.html

@RestController
public class StarterEncryptionController {

    //create database
    HashMap<String, User> database = new HashMap<>();

    @Value("${jwt.key}")
    private String secret;

//    SecretKey key = Keys.secretKeyFor(SignatureAlgorithm.ES256);
//    String base64Key = Encoders.BASE64URL.encode(key.getEncoded());

    //env import
    @Autowired
    Environment env;

    @GetMapping("/test")
    public String testGet() {

        return "Hey! The test worked!!";
    }

    @GetMapping("/all")
    public Object getAllUsers () {

        return database;// return database
    }
    //route for signup test (bcrypt hash)
    @PostMapping("/signup")
    public User signUp(
            @RequestBody User user
            //grab userdata from body
    ) {
        //hash the password is the first step
        user.setId();
        String hashedPassword = BCrypt.hashpw(user.password, BCrypt.gensalt());
        user.password = hashedPassword;
        //next step is to then store in the DB

        database.put(user.username, user);
        return user;
    }

    private Key getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secret);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    //route for sign-in test (bcrypt compare + jwt)
    @PutMapping("/signin")
    public String signIn(@RequestBody User user) {
        try {
            User loginUser = database.get(user.username);
            String unhashed = user.password;
            String hashedPW = loginUser.password;
            boolean credsMatch = BCrypt.checkpw(unhashed, hashedPW);
            if (!credsMatch) {
                return "Login failed: credentials don't match";
            }
            //now that we know the passwords match, we can create the jwt
            Instant now = Instant.now();

            Date issuedAt = Date.from(now);
            Date expiresAt = Date.from(now.plus(2, ChronoUnit.HOURS));


            String jwt = Jwts.builder()
                    .setSubject("user-auth")
                    .setIssuedAt(issuedAt)
                    .setExpiration(expiresAt)
                    .claim("id", loginUser.id)
                    .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                    .compact();
            return jwt;
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return "jwt";
    }

    @GetMapping("/testjwt")
    public String testJWT (
            //grab jwt from body
    ) {


        return "temp";
    }

}
