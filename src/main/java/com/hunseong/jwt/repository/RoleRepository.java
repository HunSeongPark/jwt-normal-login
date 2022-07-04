package com.hunseong.jwt.repository;

import com.hunseong.jwt.domain.Role;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * @author : Hunseong-Park
 * @date : 2022-07-04
 */
public interface RoleRepository extends JpaRepository<Role, Long> {
    Role findByName(String name);
}
