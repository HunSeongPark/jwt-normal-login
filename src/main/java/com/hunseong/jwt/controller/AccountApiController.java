package com.hunseong.jwt.controller;

import com.hunseong.jwt.domain.dto.AccountRequestDto;
import com.hunseong.jwt.domain.dto.RoleToUserRequestDto;
import com.hunseong.jwt.service.AccountService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

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
}
