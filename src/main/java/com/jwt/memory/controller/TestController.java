package com.jwt.memory.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Endpoint de prueba para verificar autenticación JWT.
 * Solo accesible si se envía un access token válido en Authorization header.
 */
@RestController
@RequestMapping("/api")
public class TestController {

    @GetMapping("/hello")
    public String hello() {
        return "Hola, estás autenticado";
    }

    @GetMapping("/public")
    public String publicHello() {
        return "Hola, este endpoint es público";
    }
}
