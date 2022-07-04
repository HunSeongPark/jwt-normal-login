package com.hunseong.jwt.service;

import com.hunseong.jwt.domain.dto.AccountRequestDto;

/**
 * @author : Hunseong-Park
 * @date : 2022-07-04
 */
public interface AccountService {
    Long saveAccount(AccountRequestDto dto);
}
