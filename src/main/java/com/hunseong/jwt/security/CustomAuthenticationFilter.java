package com.hunseong.jwt.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Component;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;

import static com.hunseong.jwt.security.JwtUtil.AT_EXP_TIME;
import static com.hunseong.jwt.security.JwtUtil.RT_EXP_TIME;

/**
 * @author : Hunseong-Park
 * @date : 2022-07-04
 */
@Slf4j
@Component
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    public final String JWT_SECRET_KEY;

    public CustomAuthenticationFilter(
            @Value("${JWT_SECRET_KEY}") String secret,
            AuthenticationManager authenticationManager
    ) {
        this.JWT_SECRET_KEY = secret;
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        log.info("CustomAuthenticationFilter - attemptAuthentication()");
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, password);
        return authenticationManager.authenticate(token);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        User user = (User) authResult.getPrincipal();
        String accessToken = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + AT_EXP_TIME))
                .withClaim("roles", user.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList())
                .withIssuedAt(new Date(System.currentTimeMillis()))
                .sign(Algorithm.HMAC256(JWT_SECRET_KEY));
        String refreshToken = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + RT_EXP_TIME))
                .withIssuedAt(new Date(System.currentTimeMillis()))
                .sign(Algorithm.HMAC256(JWT_SECRET_KEY));

        // Access Token , Refresh Token 프론트 단에 Response Header로 전달
        response.setHeader("access_token", accessToken);
        response.setHeader("refresh_token", refreshToken);
    }
}
