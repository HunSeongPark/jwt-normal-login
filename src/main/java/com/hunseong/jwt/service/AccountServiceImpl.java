package com.hunseong.jwt.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.hunseong.jwt.domain.Account;
import com.hunseong.jwt.domain.Role;
import com.hunseong.jwt.domain.dto.AccountRequestDto;
import com.hunseong.jwt.domain.dto.RoleToUserRequestDto;
import com.hunseong.jwt.repository.AccountRepository;
import com.hunseong.jwt.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

import static com.hunseong.jwt.security.JwtConstants.*;

/**
 * @author : Hunseong-Park
 * @date : 2022-07-04
 */
@Slf4j
@Transactional
@RequiredArgsConstructor
@Service
public class AccountServiceImpl implements AccountService, UserDetailsService {

    private final AccountRepository accountRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Account account = accountRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("UserDetailsService - loadUserByUsername : 사용자를 찾을 수 없습니다."));

        List<SimpleGrantedAuthority> authorities = account.getRoles()
                .stream().map(role -> new SimpleGrantedAuthority(role.getName())).toList();

        return new User(account.getUsername(), account.getPassword(), authorities);
    }

    @Override
    public Long saveAccount(AccountRequestDto dto) {
        validateDuplicateUsername(dto);
        dto.encodePassword(passwordEncoder.encode(dto.getPassword()));
        return accountRepository.save(dto.toEntity()).getId();
    }

    private void validateDuplicateUsername(AccountRequestDto dto) {
        if (accountRepository.existsByUsername(dto.getUsername())) {
            throw new RuntimeException("이미 존재하는 ID입니다.");
        }
    }

    @Override
    public Long saveRole(String roleName) {
        validateDuplicateRoleName(roleName);
        return roleRepository.save(new Role(roleName)).getId();
    }

    private void validateDuplicateRoleName(String roleName) {
        if (roleRepository.existsByName(roleName)) {
            throw new RuntimeException("이미 존재하는 Role입니다.");
        }
    }

    @Override
    public Long addRoleToUser(RoleToUserRequestDto dto) {
        Account account = accountRepository.findByUsername(dto.getUsername()).orElseThrow(() -> new RuntimeException("사용자를 찾을 수 없습니다."));
        Role role = roleRepository.findByName(dto.getRoleName()).orElseThrow(() -> new RuntimeException("ROLE을 찾을 수 없습니다."));
        account.getRoles().add(role);
        return account.getId();
    }

    // =============== TOKEN ============ //

    @Override
    public void updateRefreshToken(String username, String refreshToken) {
        Account account = accountRepository.findByUsername(username).orElseThrow(() -> new RuntimeException("사용자를 찾을 수 없습니다."));
        account.updateRefreshToken(refreshToken);
    }

    @Override
    public Map<String, String> refresh(String refreshToken) {
        JWTVerifier verifier = JWT.require(Algorithm.HMAC256(JWT_SECRET)).build();
        DecodedJWT decodedJWT = verifier.verify(refreshToken);
        long now = System.currentTimeMillis();
        String username = decodedJWT.getSubject();
        Account account = accountRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("사용자를 찾을 수 없습니다."));
        // TODO refresh token 만료 시 에러메시지 -> ExceptionHandler에서 처리 TokenExpiredException
        // TODO RT 유효하지 않을 시 에러메시지 -> ExceptionHandler에서 처리 JWTVerificationException
        String accessToken = JWT.create()
                .withSubject(account.getUsername())
                .withExpiresAt(new Date(now + AT_EXP_TIME))
                .withClaim("roles", account.getRoles().stream().map(Role::getName)
                        .collect(Collectors.toList()))
                .sign(Algorithm.HMAC256(JWT_SECRET));

        Map<String, String> accessTokenResponseMap = new HashMap<>();

        // Refresh Token 만료시간 계산해 1개월 미만일 시 refresh token도 발급
        long refreshExpireTime = decodedJWT.getClaim("exp").asLong() * 1000;

        long diffDays = (refreshExpireTime - now) / 1000 / (24 * 3600);
        long diffMin = (refreshExpireTime - now) / 1000 / 60;
        log.info("========= DIFFDAYS : {} =========", diffDays);
        log.info("========= DIFFMIN : {} =========", diffMin);
        log.info("========= refreshTime : {} =========", LocalDateTime.ofInstant(Instant.ofEpochMilli(refreshExpireTime),
                TimeZone.getDefault().toZoneId()));
        log.info("========= now : {} =========", LocalDateTime.ofInstant(Instant.ofEpochMilli(now),
                TimeZone.getDefault().toZoneId()));
        if (diffMin < 5) {
            String newRefreshToken = JWT.create()
                    .withSubject(account.getUsername())
                    .withExpiresAt(new Date(now + RT_EXP_TIME))
                    .sign(Algorithm.HMAC256(JWT_SECRET));
            accessTokenResponseMap.put(RT_HEADER, newRefreshToken);
            account.updateRefreshToken(newRefreshToken);
        }

        accessTokenResponseMap.put(AT_HEADER, accessToken);
        return accessTokenResponseMap;
    }
}
