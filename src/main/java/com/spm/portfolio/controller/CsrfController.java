package com.spm.portfolio.controller;

import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Map;

@RestController
public class CsrfController {

    @GetMapping("/api/csrf")
    public Mono<Map<String, String>> getCsrfToken(ServerWebExchange exchange) {

        return exchange.getFormData().then(
                Mono.defer(() -> {
                    Mono<CsrfToken> csrfTokenMono = exchange.getAttribute(CsrfToken.class.getName());
                    return csrfTokenMono
                            .map(token -> Map.of("token", token.getToken()))
                            .switchIfEmpty(Mono.just(Map.of("token", "")));
                })
        );
    }
}
