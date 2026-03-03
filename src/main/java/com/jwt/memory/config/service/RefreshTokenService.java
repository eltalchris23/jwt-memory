package com.jwt.memory.config.service;

import com.jwt.memory.config.RefreshToken;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class RefreshTokenService {

    // Storage concurrente para seguridad en multi-hilo
    private final Map<String, RefreshToken> store = new ConcurrentHashMap<>();

    // Expiración configurable en ms (ej: 7 días)
    private static final long REFRESH_EXPIRATION = 7L * 24 * 60 * 60 * 1000;

    /**
     * Crear refresh token
     */
    public RefreshToken create(String username, String tokenValue) {
        RefreshToken rt = new RefreshToken();
        rt.setToken(tokenValue);
        rt.setUsername(username);
        rt.setExpiration(Instant.now().plusMillis(REFRESH_EXPIRATION));

        store.put(rt.getToken(), rt);
        return rt;
    }

    /**
     * Validar refresh token
     */
    public RefreshToken validate(String token) {
        RefreshToken rt = store.get(token);

        if (rt == null)
            throw new RefreshTokenNotFoundException("Refresh token inválido");

        if (rt.getExpiration().isBefore(Instant.now())) {
            store.remove(token);
            throw new RefreshTokenExpiredException("Refresh token expirado");
        }

        return rt;
    }

    /**
     * Eliminar refresh token (logout o revocación)
     */
    public void delete(String token) {
        store.remove(token);
    }

    /**
     * Limpiar tokens expirados
     */
    public void cleanupExpiredTokens() {
        Instant now = Instant.now();
        store.values().removeIf(rt -> rt.getExpiration().isBefore(now));
    }

    /**
     * Cargar UserDetails para refresh token (simulado, reemplazar con DB en producción)
     */
    public UserDetails loadUserByUsername(String username) {
        RefreshToken rt = store.values().stream()
                .filter(r -> r.getUsername().equals(username))
                .findFirst()
                .orElseThrow(() -> new RefreshTokenNotFoundException("Usuario no encontrado"));

        // En memoria solo admin/roles de ejemplo
        return User.builder()
                .username(rt.getUsername())
                .password("") // no necesario para refresh
                .roles("ADMIN")
                .build();
    }

    // ===== Excepciones personalizadas =====
    public static class RefreshTokenNotFoundException extends RuntimeException {
        public RefreshTokenNotFoundException(String msg) { super(msg); }
    }

    public static class RefreshTokenExpiredException extends RuntimeException {
        public RefreshTokenExpiredException(String msg) { super(msg); }
    }
}
