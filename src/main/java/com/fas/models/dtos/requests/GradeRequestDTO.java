package com.fas.models.dtos.requests;

import com.fas.models.entities.Grade;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.UUID;

@Data
public class GradeRequestDTO {
    private UUID id;

    private String code;

    private boolean status = true;

    private LocalDateTime createdAt = LocalDateTime.now();

    private LocalDateTime updatedAt = LocalDateTime.now();

    public Grade getGrade() {
        return new Grade(id, code, status, createdAt, updatedAt);
    }

}
