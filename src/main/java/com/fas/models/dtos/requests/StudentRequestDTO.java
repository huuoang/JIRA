package com.fas.models.dtos.requests;

import com.fas.models.entities.Major;
import com.fas.models.entities.Student;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.Date;
import java.util.UUID;

@Data
public class StudentRequestDTO {
    private String email;

    private String studentCode;

    private String username;

    private String firstName;

    private String middleName;

    private String lastName;

    private String profileImage;

    private String phone;

    private String address;

    private Date birthDay;

    private String idCard;

    private boolean gender;

    private LocalDateTime createAt = LocalDateTime.now();

    private LocalDateTime updateAt = LocalDateTime.now();

    private boolean status = true;

    @NotNull(message = "Major must not be blank")
    private UUID majorId;

    @NotNull(message = "Campus must not be blank")
    private Long campusId;

    public Student getStudent() {
        return new Student(email, studentCode, username, firstName, middleName, lastName, profileImage, phone, address, birthDay, idCard, gender, createAt, updateAt, status, majorId, campusId);
    }
}
