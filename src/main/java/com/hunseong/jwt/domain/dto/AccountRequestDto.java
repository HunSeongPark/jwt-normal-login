package com.hunseong.jwt.domain.dto;

import com.hunseong.jwt.domain.Account;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * @author : Hunseong-Park
 * @date : 2022-07-04
 */
@Getter
@AllArgsConstructor
@NoArgsConstructor
public class AccountRequestDto {
    private String username;
    private String password;

    public Account toEntity() {
        return Account.builder()
                .username(username)
                .password(password)
                .build();
    }

    public void encodePassword(String encodedPassword) {
        this.password = encodedPassword;
    }
}
