package com.fas.repositories;

import com.fas.models.entities.Course;
import com.fas.models.entities.Major;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.UUID;

public interface CourseRepository extends JpaRepository<Course, UUID> {
    Course findByCode(String code);

    @Query("SELECT m FROM Course m WHERE m.code = :code AND m.id != :id")
    Course findByUniqueCode(@Param("code") String code, @Param("id") UUID id);
}
