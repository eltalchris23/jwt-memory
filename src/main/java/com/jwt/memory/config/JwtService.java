package com.jwt.memory.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.List;
import java.util.Map;

@Service
public class JwtService {

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.accessExpiration}")   // en ms
    private Long accessExpiration;

    @Value("${jwt.refreshExpiration}")  // en ms
    private Long refreshExpiration;

    private Key getSigningKey() {
        return Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    /* =========================
       GENERAR ACCESS TOKEN
       ========================= */
    public String generateAccessToken(UserDetails userDetails) {
        Map<String, Object> claims = Map.of(
                "roles", userDetails.getAuthorities()
                        .stream()
                        .map(a -> a.getAuthority())
                        .toList()
        );
        return generateToken(userDetails.getUsername(), claims, accessExpiration);
    }

    /* =========================
       GENERAR REFRESH TOKEN
       ========================= */
    public String generateRefreshToken(UserDetails userDetails) {
        // No se incluyen roles, solo username y expiración
        return generateToken(userDetails.getUsername(), Map.of(), refreshExpiration);
    }

    /* =========================
       MÉTODO PRIVADO DE GENERACIÓN
       ========================= */
    private String generateToken(String username, Map<String, Object> extraClaims, Long expirationTime) {
        return Jwts.builder()
                .setClaims(extraClaims)
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expirationTime))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    /* =========================
       VALIDAR TOKEN
       ========================= */
    public void validateToken(String token) throws JwtException {
        try {
            extractAllClaims(token);
        } catch (ExpiredJwtException e) {
            throw new RuntimeException("Token expirado");
        } catch (JwtException | IllegalArgumentException e) {
            throw new RuntimeException("Token inválido");
        }
    }

    /* =========================
       EXTRAER DATOS
       ========================= */
    public String extractUsername(String token) {
        return extractAllClaims(token).getSubject();
    }

    public List<String> extractRoles(String token) {
        Object roles = extractAllClaims(token).get("roles");
        if (roles instanceof List<?> list) {
            return list.stream()
                    .map(String::valueOf)
                    .toList();
        }
        return List.of();
    }

    /* =========================
       EXTRAER TODAS LAS CLAIMS
       ========================= */
    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}
