package com.spm.portfolio.config;

import com.spm.portfolio.repository.impl.JwtSecurityContextRepository;
import com.spm.portfolio.service.CustomUserDetailsService;
import com.spm.portfolio.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository;
import org.springframework.security.web.server.csrf.ServerCsrfTokenRequestAttributeHandler;
import org.springframework.web.cors.CorsConfiguration;
import reactor.core.publisher.Mono;

import java.util.Collections;
import java.util.List;

@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final CustomUserDetailsService userDetailsService;
    private final JwtUtil jwtUtil;
    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
                //.csrf(ServerHttpSecurity.CsrfSpec::disable)
                .csrf(csrf -> csrf
                        .csrfTokenRepository(CookieServerCsrfTokenRepository.withHttpOnlyFalse())
                        .csrfTokenRequestHandler(new ServerCsrfTokenRequestAttributeHandler()) // Step 2
                )
                .cors(cors -> cors.configurationSource(request -> {
                    CorsConfiguration config = new CorsConfiguration();
                    config.setAllowedOrigins(List.of("http://localhost:4200","http://192.168.0.121:4200")); // Allow UI URL
                    config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
                    config.setAllowedHeaders(List.of(
                            "Authorization",
                            "Content-Type",
                            "X-XSRF-TOKEN"    //  required for CSRF header to pass
                    ));

                    config.setExposedHeaders(List.of(
                            "XSRF-TOKEN"       //  allows browser to read the Set-Cookie header for CSRF
                    ));

                    config.setAllowCredentials(true);
                    return config;
                }))
                .authorizeExchange(exchange ->
                        exchange.pathMatchers(
                                "/swagger-ui/**",
                                        "/swagger-ui.html",
                                "/v3/api-docs/**",
                                "/webjars/**",
                                "/api-docs/**",
                                        "/api/auth/**", "/api/user/**","/actuator/**","/api/csrf/**"
                        ).permitAll()
                        .pathMatchers("/api/av/stock/**","/api/stocksList/**","/api/portfolio/**")
                                .authenticated()
                ).authenticationManager(reactiveAuthenticationManager())

                .securityContextRepository(new JwtSecurityContextRepository(jwtUtil)) // Store authentication state

                .build();
    }


    @Bean
    public ReactiveAuthenticationManager reactiveAuthenticationManager() {
        return authentication -> {
            String token = authentication.getCredentials().toString();
            String username = jwtUtil.extractUsername(token);

            if (jwtUtil.validateToken(token)) {
                List<SimpleGrantedAuthority> authorities = Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"));
                return Mono.just(new UsernamePasswordAuthenticationToken(username, null, authorities));
            } else {
                return Mono.empty();
            }
        };
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
