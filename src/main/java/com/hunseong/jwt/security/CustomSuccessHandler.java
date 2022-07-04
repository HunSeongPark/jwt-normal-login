package com.hunseong.jwt.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.hunseong.jwt.repository.AccountRepository;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static com.hunseong.jwt.security.JwtUtil.*;
import static com.hunseong.jwt.security.JwtUtil.RT_HEADER;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

/**
 * @author : Hunseong-Park
 * @date : 2022-07-04
 */
@RequiredArgsConstructor
@Component
public class CustomSuccessHandler implements AuthenticationSuccessHandler {

    private final AccountRepository accountRepository;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        User user = (User) authentication.getPrincipal();
        String accessToken = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + AT_EXP_TIME))
                .withClaim("roles", user.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList())
                .withIssuedAt(new Date(System.currentTimeMillis()))
                .sign(Algorithm.HMAC256(JWT_SECRET));
        String refreshToken = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + RT_EXP_TIME))
                .withIssuedAt(new Date(System.currentTimeMillis()))
                .sign(Algorithm.HMAC256(JWT_SECRET));

        // Access Token , Refresh Token 프론트 단에 Response Header로 전달
        response.setContentType(APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("utf-8");
        response.setHeader(AT_HEADER, accessToken);
        response.setHeader(RT_HEADER, refreshToken);

        Map<String, String> responseMap = new HashMap<>();
        responseMap.put(AT_HEADER, accessToken);
        responseMap.put(RT_HEADER, refreshToken);
        new ObjectMapper().writeValue(response.getWriter(), responseMap);
    }
}
