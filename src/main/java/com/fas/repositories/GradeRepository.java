package com.fas.repositories;

import com.fas.models.entities.Grade;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface GradeRepository extends JpaRepository<Grade, UUID> {
    Grade findByCode(String code);
}
