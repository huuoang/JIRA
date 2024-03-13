package com.fas.repositories;

import com.fas.models.entities.Major;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.UUID;

public interface MajorRepository extends JpaRepository<Major, UUID> {
    Major findByCode(String code);


    @Query("SELECT m FROM Major m WHERE m.code = :code AND m.id != :id")
    Major findByUniqueCode(@Param("code") String code, @Param("id") UUID id);
}
