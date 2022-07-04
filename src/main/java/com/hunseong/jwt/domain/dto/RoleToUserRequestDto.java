package com.hunseong.jwt.domain.dto;

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
public class RoleToUserRequestDto {
    private String username;
    private String roleName;
}
