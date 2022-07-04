package com.hunseong.jwt.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.hunseong.jwt.exception.ErrorResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

import static com.hunseong.jwt.security.JwtConstants.JWT_SECRET;
import static com.hunseong.jwt.security.JwtConstants.TOKEN_HEADER_PREFIX;
import static javax.servlet.http.HttpServletResponse.SC_BAD_REQUEST;
import static javax.servlet.http.HttpServletResponse.SC_UNAUTHORIZED;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

/**
 * @author : Hunseong-Park
 * @date : 2022-07-04
 */
@Slf4j
@Component
public class CustomAuthorizationFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String servletPath = request.getServletPath();
        String authrizationHeader = request.getHeader(AUTHORIZATION);

        // 로그인, 리프레시 요청이라면 토큰 검사하지 않음
        if (servletPath.equals("/api/login") || servletPath.equals("/api/refresh")) {
            filterChain.doFilter(request, response);
        } else if (authrizationHeader == null || !authrizationHeader.startsWith(TOKEN_HEADER_PREFIX)) {
            // 토큰값이 없거나 정상적이지 않다면 400 오류
            log.info("CustomAuthorizationFilter : JWT Token이 존재하지 않습니다.");
            response.setStatus(SC_BAD_REQUEST);
            response.setContentType(APPLICATION_JSON_VALUE);
            response.setCharacterEncoding("utf-8");
            ErrorResponse errorResponse = new ErrorResponse(400, "JWT Token이 존재하지 않습니다.");
            new ObjectMapper().writeValue(response.getWriter(), errorResponse);
        } else {
            try {
                String accessToken = authrizationHeader.substring(TOKEN_HEADER_PREFIX.length());
                JWTVerifier verifier = JWT.require(Algorithm.HMAC256(JWT_SECRET)).build();
                DecodedJWT decodedJWT = verifier.verify(accessToken);
                List<String> strAuthorities = decodedJWT.getClaim("roles").asList(String.class);
                List<SimpleGrantedAuthority> authorities = strAuthorities.stream().map(SimpleGrantedAuthority::new).toList();
                String username = decodedJWT.getSubject();
                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, null, authorities);
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                filterChain.doFilter(request, response);
            } catch (TokenExpiredException e) {
                log.info("CustomAuthorizationFilter : Access Token이 만료되었습니다.");
                response.setStatus(SC_UNAUTHORIZED);
                response.setContentType(APPLICATION_JSON_VALUE);
                response.setCharacterEncoding("utf-8");
                ErrorResponse errorResponse = new ErrorResponse(401, "Access Token이 만료되었습니다.");
                new ObjectMapper().writeValue(response.getWriter(), errorResponse);
            } catch (Exception e) {
                log.info("CustomAuthorizationFilter : JWT 토큰이 잘못되었습니다. message : {}", e.getMessage());
                response.setStatus(SC_BAD_REQUEST);
                response.setContentType(APPLICATION_JSON_VALUE);
                response.setCharacterEncoding("utf-8");
                ErrorResponse errorResponse = new ErrorResponse(400, "잘못된 JWT Token 입니다.");
                new ObjectMapper().writeValue(response.getWriter(), errorResponse);
            }
        }
    }
}
