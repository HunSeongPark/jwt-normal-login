package com.hunseong.jwt.exception;

import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * @author : Hunseong-Park
 * @date : 2022-07-04
 */
@Getter
@AllArgsConstructor
public class ErrorResponse {
    private final int errorCode;
    private final String errorMessage;
}
