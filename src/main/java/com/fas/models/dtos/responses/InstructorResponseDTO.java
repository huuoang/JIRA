package com.fas.models.dtos.responses;

import com.fas.models.entities.Campus;
import com.fas.models.entities.Instructor;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.Date;
import java.util.UUID;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class InstructorResponseDTO {

    private UUID id;
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

    private boolean gender;

    private boolean status = true;

    private Campus campus;

    private LocalDateTime createAt = LocalDateTime.now();
    private LocalDateTime updateAt = LocalDateTime.now();

    public InstructorResponseDTO(Instructor instructor) {
        this.id = instructor.getId();
        this.email = instructor.getEmail();
        this.username = instructor.getUsername();
        this.firstName = instructor.getFirstName();
        this.middleName = instructor.getMiddleName();
        this.lastName = instructor.getLastName();
        this.profileImage = instructor.getProfileImage();
        this.phone = instructor.getPhone();
        this.address = instructor.getAddress();
        this.birthDay = instructor.getBirthDay();
        this.idCard = instructor.getIdCard();
        this.gender = instructor.isGender();
        this.status = instructor.isStatus();
        this.campus = instructor.getCampus();
        this.createAt = instructor.getCreateAt();
        this.updateAt = instructor.getUpdateAt();
    }
}
