package com.spm.portfolio.controller;

import com.spm.portfolio.dto.LoginRequestDto;
import com.spm.portfolio.dto.TokenDto;
import com.spm.portfolio.exception.InvalidCredentialsException;
import com.spm.portfolio.exception.InvalidTokenException;
import com.spm.portfolio.service.CustomUserDetailsService;
import com.spm.portfolio.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.time.Duration;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    private final CustomUserDetailsService userDetailsService;
    private final JwtUtil jwtUtil;
    private final BCryptPasswordEncoder passwordEncoder;


    @GetMapping(value = "/token", produces = MediaType.APPLICATION_JSON_VALUE)
    public Mono<Boolean> validateToken(@CookieValue(name = "jwt", required = false) String jwt) {
        if (jwt == null || jwt.isBlank()) {
            throw new InvalidTokenException("Missing JWT cookie");
        }

        try {
            return Mono.just(jwtUtil.validateToken(jwt));
        } catch (Exception ex) {
            throw new InvalidTokenException("Invalid or expired token");
        }
    }


    @PostMapping("/logout")
    public Mono<ResponseEntity<Void>> logout(ServerHttpResponse response) {
        // Clear the jwt cookie by setting maxAge to 0
        // Invalidate jwt cookie
        ResponseCookie deleteJwt = ResponseCookie.from("jwt", "")
                .httpOnly(true)
                .secure(true)
                .path("/")
                .maxAge(Duration.ZERO)
                .sameSite("Lax")
                .build();

        // Invalidate XSRF-TOKEN cookie
        ResponseCookie deleteXsrf = ResponseCookie.from("XSRF-TOKEN", "")
                .httpOnly(false) // important: must be false so Angular can read it
                .secure(true)
                .path("/")
                .maxAge(Duration.ZERO)
                .sameSite("Lax")
                .build();

        response.addCookie(deleteJwt);
        response.addCookie(deleteXsrf);
        return Mono.just(ResponseEntity.ok().build());
    }

    @PostMapping("/login")
    public Mono<TokenDto> login(@RequestBody LoginRequestDto loginRequestDto, ServerHttpResponse response) {
        return userDetailsService.findByUserId(loginRequestDto.getUserId())
                .flatMap(userDetails -> {
                    if (passwordEncoder.matches(loginRequestDto.getPassword(), userDetails.getPassword())) {
                        String jwtToken = jwtUtil.generateToken(loginRequestDto.getUserId());
                        ResponseCookie jwtCookie = ResponseCookie.from("jwt", jwtToken)
                                .httpOnly(true)
                                .secure(true)
                                .sameSite("Lax")
                                .path("/")
                                .maxAge(Duration.ofHours(1))
                                .build();

                        response.addCookie(jwtCookie);

                        //  Return the token in body (to keep frontend logic unchanged)
                        TokenDto tokenDto = TokenDto.builder()
                                .userId(loginRequestDto.getUserId())
                                .userName(userDetails.getUsername())
                                .build();

                        return Mono.just(tokenDto);
                    } else {
                        return Mono.error(new InvalidCredentialsException("Invalid credentials"));
                    }
                });
    }

}
