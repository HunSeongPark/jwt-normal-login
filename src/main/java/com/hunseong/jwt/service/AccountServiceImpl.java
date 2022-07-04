package com.hunseong.jwt.service;

import com.hunseong.jwt.domain.dto.AccountRequestDto;
import com.hunseong.jwt.repository.AccountRepository;
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
}
