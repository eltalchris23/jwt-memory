package com.jwt.memory.config;

import lombok.Getter;
import lombok.Setter;

import java.time.Instant;

@Getter
@Setter
public class RefreshToken {
    private String token;
    private String username;
    private Instant expiration;
}
