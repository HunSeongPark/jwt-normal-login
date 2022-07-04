package com.hunseong.jwt.security;

/**
 * @author : Hunseong-Park
 * @date : 2022-07-04
 */
public class JwtConstants {

    // Expiration Time
    public static final int AT_EXP_TIME =  1 * (1000 * 60);
    public static final int RT_EXP_TIME =  10 * (1000 * 60);

    // Secret
    public static final String JWT_SECRET = "jwt_secret_key_hunseong_secret_key_jwt";

    // Header
    public static final String AT_HEADER = "access_token";
    public static final String RT_HEADER = "refresh_token";
    public static final String TOKEN_HEADER_PREFIX = "Bearer ";
}
