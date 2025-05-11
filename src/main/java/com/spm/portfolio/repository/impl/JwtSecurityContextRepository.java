
package com.spm.portfolio.repository.impl;

import com.spm.portfolio.util.JwtUtil;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Collections;
import java.util.List;

public class JwtSecurityContextRepository implements ServerSecurityContextRepository {
    private final JwtUtil jwtUtil;

    public JwtSecurityContextRepository(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    public Mono<Void> save(ServerWebExchange exchange, SecurityContext context) {
        return Mono.empty(); // No need to store authentication state
    }

    @Override
    public Mono<SecurityContext> load(ServerWebExchange exchange) {
        return extractToken(exchange)
                .filter(jwtUtil::validateToken)
                .map(jwtUtil::extractUsername)
                .map(username -> {
                    List<SimpleGrantedAuthority> authorities =
                            Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"));
                    var auth = new UsernamePasswordAuthenticationToken(username, null, authorities);
                    return new SecurityContextImpl(auth);
                });
    }
    private Mono<String> extractToken(ServerWebExchange exchange) {
       // use http cookie
        HttpCookie jwtCookie = exchange.getRequest().getCookies().getFirst("jwt");
        if (jwtCookie != null) {
            return Mono.just(jwtCookie.getValue());
        }

        return Mono.empty();
    }
}
