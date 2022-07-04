package com.hunseong.jwt.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * @author : Hunseong-Park
 * @date : 2022-07-04
 */
@Component
public class JwtUtil {

    @Value("${JWT_SECRET_KEY}")
    public String JWT_SECRET;

    public static final int AT_EXP_TIME =  1 * (1000 * 60);
    public static final int RT_EXP_TIME =  10 * (1000 * 60);
}
