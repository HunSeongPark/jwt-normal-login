package com.hunseong.jwt.controller;

import com.hunseong.jwt.domain.dto.AccountRequestDto;
import com.hunseong.jwt.domain.dto.RoleToUserRequestDto;
import com.hunseong.jwt.service.AccountService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.util.Map;

import static com.hunseong.jwt.security.JwtConstants.*;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;

/**
 * @author : Hunseong-Park
 * @date : 2022-07-04
 */
@RequestMapping("/api")
@RequiredArgsConstructor
@RestController
public class AccountApiController {

    private final AccountService accountService;

    @PostMapping("/signup")
    public ResponseEntity<Long> signup(@RequestBody AccountRequestDto dto) {
        return ResponseEntity.ok(accountService.saveAccount(dto));
    }

    @PostMapping("/role")
    public ResponseEntity<Long> saveRole(@RequestBody String roleName) {
        return ResponseEntity.ok(accountService.saveRole(roleName));
    }

    @PostMapping("/userrole")
    public ResponseEntity<Long> addRoleToUser(@RequestBody RoleToUserRequestDto dto) {
        return ResponseEntity.ok(accountService.addRoleToUser(dto));
    }

    @GetMapping("/my")
    public ResponseEntity<String> my() {
        return ResponseEntity.ok("My");
    }

    @GetMapping("/admin")
    public ResponseEntity<String> admin() {
        return ResponseEntity.ok("Admin");
    }

    @GetMapping("/refresh")
    public ResponseEntity<Map<String, String>> refresh(HttpServletRequest request, HttpServletResponse response) {
        String authorizationHeader = request.getHeader(AUTHORIZATION);

        if (authorizationHeader == null || !authorizationHeader.startsWith(TOKEN_HEADER_PREFIX)) {
            throw new RuntimeException("JWT Token이 존재하지 않습니다.");
        }
        String refreshToken = authorizationHeader.substring(TOKEN_HEADER_PREFIX.length());
        Map<String, String> tokens = accountService.refresh(refreshToken);
        response.setHeader(AT_HEADER, tokens.get(AT_HEADER));
        if (tokens.get(RT_HEADER) != null) {
            response.setHeader(RT_HEADER, tokens.get(RT_HEADER));
        }
        return ResponseEntity.ok(tokens);
    }
}
