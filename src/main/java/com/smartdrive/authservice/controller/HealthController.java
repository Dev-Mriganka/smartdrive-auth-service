package com.smartdrive.authservice.controller;

import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/health")
public class HealthController {

    @GetMapping
    public ResponseEntity<Map<String, String>> getHealth() {
        return ResponseEntity.ok(Map.of(
            "status", "UP",
            "service", "auth-service",
            "timestamp", String.valueOf(System.currentTimeMillis())
        ));
    }

    @PostMapping("/test")
    public ResponseEntity<Map<String, String>> postTest() {
        return ResponseEntity.ok(Map.of(
            "method", "POST",
            "status", "SUCCESS",
            "message", "POST endpoint working without security"
        ));
    }
}