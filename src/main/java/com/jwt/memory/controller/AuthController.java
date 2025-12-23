package com.jwt.memory.controller;

import com.jwt.memory.config.JwtService;
import com.jwt.memory.config.RefreshToken;
import com.jwt.memory.config.service.RefreshTokenService;
import com.jwt.memory.dto.LoginRequest;
import com.jwt.memory.dto.LoginResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;

    public AuthController(AuthenticationManager authenticationManager, JwtService jwtService, RefreshTokenService refreshTokenService) {
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
        this.refreshTokenService = refreshTokenService;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {

        try {
            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    request.getUsername(),
                    request.getPassword()
            );

            Authentication authResult =
                    authenticationManager.authenticate(authentication);

            // Obtenemos roles
            List<String> roles = authResult.getAuthorities()
                    .stream()
                    .map(GrantedAuthority::getAuthority)
                    .toList();

            Map<String, Object> claims = new HashMap<>();
            claims.put("roles", roles);

            String token = jwtService.generateToken(
                    request.getUsername(),
                    claims
            );

            RefreshToken refreshToken =
                    refreshTokenService.create(request.getUsername());

            return ResponseEntity.ok(new LoginResponse(token, refreshToken.getToken()));

        } catch (BadCredentialsException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Usuario o contraseña incorrectos");
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@RequestBody String refreshToken) {

        RefreshToken rt =
                refreshTokenService.validate(refreshToken);

        Map<String, Object> claims = new HashMap<>();
        // aquí podrías volver a cargar roles si usas BD

        String newAccessToken =
                jwtService.generateToken(rt.getUsername(), claims);

        return ResponseEntity.ok(
                Map.of("accessToken", newAccessToken)
        );
    }

}
