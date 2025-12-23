package com.jwt.memory.config.service;

import com.jwt.memory.config.RefreshToken;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Service
public class RefreshTokenService {

    private final Map<String, RefreshToken> store = new HashMap<>();

    private static final long REFRESH_EXPIRATION =
            3 * 60 * 1000; // 3 minutos
            //1000 * 60 * 60; // 1 hora
            //1000L * 60 * 60 * 24; // 24 horas

    public RefreshToken create(String username) {
        RefreshToken rt = new RefreshToken();
        rt.setToken(UUID.randomUUID().toString());
        rt.setUsername(username);
        rt.setExpiration(
                Instant.now().plusMillis(REFRESH_EXPIRATION)
        );

        store.put(rt.getToken(), rt);
        return rt;
    }

    public RefreshToken validate(String token) {
        RefreshToken rt = store.get(token);

        if (rt == null)
            throw new RuntimeException("Refresh token inválido");

        if (rt.getExpiration().isBefore(Instant.now())) {
            store.remove(token);
            throw new RuntimeException("Refresh token expirado");
        }

        return rt;
    }

    public void delete(String token) {
        store.remove(token);
    }
}
