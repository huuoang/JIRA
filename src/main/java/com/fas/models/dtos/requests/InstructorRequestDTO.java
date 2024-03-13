package com.fas.models.dtos.requests;

import com.fas.models.entities.Instructor;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.validation.constraints.*;
import lombok.Data;
import org.hibernate.validator.constraints.URL;

import java.time.LocalDateTime;
import java.util.Date;
import java.util.UUID;

@Data
public class InstructorRequestDTO {
    private String email;

    private String username;

    private String firstName;

    private String middleName;

    private String lastName;

    private String profileImage;

    private String phone;

    private String address;

    private Date birthDay;

    private String idCard;

    @NotNull(message = "Campus must not be blank")
    private Long campusId;

    private boolean gender;

    private boolean status = true;

    private LocalDateTime createAt = LocalDateTime.now();

    private LocalDateTime updateAt = LocalDateTime.now();
    public Instructor getIntructor() {
        return new Instructor(email, username, firstName, middleName, lastName, profileImage, phone, address, birthDay, idCard, campusId, gender, status, createAt, updateAt);
    }

}
