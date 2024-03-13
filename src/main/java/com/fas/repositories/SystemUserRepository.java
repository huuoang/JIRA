package com.fas.repositories;

import com.fas.models.entities.SystemUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.UUID;

public interface SystemUserRepository extends JpaRepository<SystemUser, UUID> {

    SystemUser findByEmail(String email);
}
