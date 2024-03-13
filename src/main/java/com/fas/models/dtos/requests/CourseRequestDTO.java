package com.fas.models.dtos.requests;

import com.fas.models.entities.Course;
import com.fas.models.entities.Student;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.UUID;


@Data
public class CourseRequestDTO {
    private UUID id;

    private String code;

    private String name;

    private String description;

    private Integer noCredit;

    private boolean status = true;

    private LocalDateTime createdAt = LocalDateTime.now();

    private LocalDateTime updatedAt = LocalDateTime.now();

    public Course getCourse() {
        return new Course(id, code, name, description, noCredit, status, createdAt, updatedAt);
    }
}
