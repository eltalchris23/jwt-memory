package com.jwt.memory.controller;

import com.jwt.memory.config.JwtService;
import com.jwt.memory.config.RefreshToken;
import com.jwt.memory.config.service.RefreshTokenService;
import com.jwt.memory.dto.LoginRequest;
import com.jwt.memory.dto.LoginResponse;
import com.jwt.memory.dto.RefreshRequest;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;

    public AuthController(AuthenticationManager authenticationManager,
                          JwtService jwtService,
                          RefreshTokenService refreshTokenService) {
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
        this.refreshTokenService = refreshTokenService;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        try {
            Authentication auth = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getUsername(),
                            request.getPassword()
                    )
            );

            UserDetails userDetails = (UserDetails) auth.getPrincipal();

            String accessToken = jwtService.generateAccessToken(userDetails);
            String refreshToken = jwtService.generateRefreshToken(userDetails);

            // Guardar refresh token en DB/cache
            RefreshToken rt = refreshTokenService.create(userDetails.getUsername(), refreshToken);

            return ResponseEntity.ok(
                    new LoginResponse(accessToken, rt.getToken())
            );

        } catch (BadCredentialsException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of(
                            "timestamp", Instant.now(),
                            "status", 401,
                            "error", "Unauthorized",
                            "message", "Usuario o contraseña incorrectos"
                    ));
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@RequestBody RefreshRequest request) {
        try {
            // Validar refresh token
            RefreshToken rt = refreshTokenService.validate(request.getRefreshToken());

            // Aquí podrías cargar roles reales si usas DB
            UserDetails userDetails = refreshTokenService.loadUserByUsername(rt.getUsername());

            String newAccessToken = jwtService.generateAccessToken(userDetails);

            return ResponseEntity.ok(
                    Map.of(
                            "accessToken", newAccessToken
                    )
            );

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of(
                            "timestamp", Instant.now(),
                            "status", 403,
                            "error", "Forbidden",
                            "message", e.getMessage()
                    ));
        }
    }

    @GetMapping("/hello")
    public ResponseEntity<?> hello() {
        return ResponseEntity.ok(
                Map.of(
                        "message", "Hola, estás autenticado ✅"
                )
        );
    }
}
