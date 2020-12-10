package com.encryption.cd;


import io.jsonwebtoken.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.security.crypto.bcrypt.BCrypt;

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
            return "Login worked!";
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return "success!";
    }

    @GetMapping("/testjwt")
    public String testJWT (
            //grab jwt from body
    ) {


        return "temp";
    }

}
