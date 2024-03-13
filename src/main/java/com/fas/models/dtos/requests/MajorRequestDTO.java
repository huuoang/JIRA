package com.fas.models.dtos.requests;

import com.fas.models.entities.Major;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.UUID;

@Data
public class MajorRequestDTO {
    private UUID id;

    private String code;

    private String name;

    private boolean status = true;

    private LocalDateTime createAt = LocalDateTime.now();

    private LocalDateTime updateAt = LocalDateTime.now();

    public Major getMajor() {
        return new Major(id, code, name,status, createAt, updateAt);
    }
}
