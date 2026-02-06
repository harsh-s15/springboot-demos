package com.example.service;

import com.example.DAO.UserRepository;
import com.example.bean.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class FileUserDetailsService implements UserDetailsService{
    private final UserRepository repo;

    public FileUserDetailsService(UserRepository repo) {
        this.repo = repo;
    }

    @Override
    public UserDetails loadUserByUsername(String username) {
        User user = repo.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException(username));

        return org.springframework.security.core.userdetails.User
                .withUsername(user.getUsername())
                .password(user.getPasswordHash())
                .roles("USER")
                .build();
    }
}
