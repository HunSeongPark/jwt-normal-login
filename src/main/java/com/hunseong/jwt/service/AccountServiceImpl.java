package com.hunseong.jwt.service;

import com.hunseong.jwt.domain.Account;
import com.hunseong.jwt.domain.Role;
import com.hunseong.jwt.domain.dto.AccountRequestDto;
import com.hunseong.jwt.domain.dto.RoleToUserRequestDto;
import com.hunseong.jwt.repository.AccountRepository;
import com.hunseong.jwt.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * @author : Hunseong-Park
 * @date : 2022-07-04
 */
@Transactional
@RequiredArgsConstructor
@Service
public class AccountServiceImpl implements AccountService {

    private final AccountRepository accountRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

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
}