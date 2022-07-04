package com.hunseong.jwt.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.hunseong.jwt.exception.ErrorResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

/**
 * @author : Hunseong-Park
 * @date : 2022-07-04
 */
@Component
public class CustomFailureHandler implements AuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("utf-8");
        ErrorResponse errorResponse = new ErrorResponse(401, "ID 또는 비밀번호가 일치하지 않습니다.");
        new ObjectMapper().writeValue(response.getWriter(), errorResponse);
    }
}
