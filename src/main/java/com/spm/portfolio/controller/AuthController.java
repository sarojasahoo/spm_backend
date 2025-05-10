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
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    private final CustomUserDetailsService userDetailsService;
    private final JwtUtil jwtUtil;
    private final BCryptPasswordEncoder passwordEncoder;

    @GetMapping(value = "/token", produces = MediaType.APPLICATION_JSON_VALUE)
    public Mono<Boolean> validateToken(@RequestHeader("Authorization") String authHeader) {

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new InvalidTokenException("Missing or invalid Authorization header");
        }

        String jwt = authHeader.substring(7);
        try {
            return Mono.just(jwtUtil.validateToken(jwt));
        } catch (Exception ex) {
            throw new InvalidTokenException("Invalid or expired token");
        }
    }


   @PostMapping("/login")
   public Mono<TokenDto> login(@RequestBody LoginRequestDto loginRequestDto) {
       return userDetailsService.findByUserId(loginRequestDto.getUserId())
               .flatMap(userDetails -> {
                   if (passwordEncoder.matches(loginRequestDto.getPassword(), userDetails.getPassword())) {
                       String jwtToken = jwtUtil.generateToken(loginRequestDto.getUserId());
                       TokenDto tokenDto = TokenDto.builder()
                               .access_token(jwtToken)
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
