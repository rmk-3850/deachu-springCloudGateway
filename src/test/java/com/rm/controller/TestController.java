package com.rm.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import reactor.core.publisher.Mono;

@RestController
public class TestController {
    @GetMapping("/api/test")
    public Mono<ResponseEntity<Void>> test(ServerHttpRequest request) {
        return Mono.just(
            ResponseEntity.ok()
                .header("X-User-Uid", request.getHeaders().getFirst("X-User-Uid"))
                .header("X-User-Roles", request.getHeaders().getFirst("X-User-Roles"))
                .build()
        );
    }
}
