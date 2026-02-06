package com.example.controller;

import com.example.DAO.UserRepository;
import com.example.bean.User;
import com.example.dto.LoginRequest;
import com.example.dto.SignupRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
public class AuthController {

    private final UserRepository repo;
    private final PasswordEncoder encoder;

    public AuthController(UserRepository repo, PasswordEncoder encoder) {
        this.repo = repo;
        this.encoder = encoder;
    }

    @GetMapping("/home")
    public ResponseEntity<?> gethome(){
        return ResponseEntity.ok("welcome to homepage");
    }

    @PostMapping("/signup")
    public ResponseEntity<?> signup(@RequestBody SignupRequest req) {

        if (repo.findByUsername(req.username()).isPresent()) {
            return ResponseEntity.badRequest().body("User exists");
        }

//        System.out.println("req.username()");

        User user = new User();
        user.setUsername(req.username());
        user.setPasswordHash(encoder.encode(req.password()));

//        System.out.println(user.toString());

        repo.save(user);
        return ResponseEntity.ok("Signup successful");
    }



    @PostMapping("/login")
    public ResponseEntity<?> login(
            @RequestBody LoginRequest req,
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        User user = repo.findByUsername(req.username())
                .orElseThrow(() -> new RuntimeException("Invalid credentials"));

        if (!encoder.matches(req.password(), user.getPasswordHash())) {
            return ResponseEntity.status(401).body("Invalid credentials");
        }

        // 1️⃣ Create Authentication
        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(
                        user.getUsername(),
                        null,
                        List.of()
                );

        // 2️⃣ Create SecurityContext
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication);

        // 3️⃣ Force session creation
        request.getSession(true);

        // 4️⃣ Persist SecurityContext properly
        HttpSessionSecurityContextRepository securityContextRepo =
                new HttpSessionSecurityContextRepository();

        securityContextRepo.saveContext(context, request, response);

        return ResponseEntity.ok("Login successful");
    }





}
