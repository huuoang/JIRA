package com.fas.models.entities;

import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.validator.constraints.URL;

import java.time.LocalDateTime;
import java.util.Date;
import java.util.UUID;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Student {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;

    @Pattern(regexp = "^[\\w!#$%&'*+/=?`{|}~^-]+@fpt\\.edu\\.vn$", message = "Email must be valid")
    private String email;

    @NotBlank(message = "Username must not be blank")
    private String username;

    @NotBlank(message = "Student Code must not be null")
    private String studentCode;

    @NotBlank(message = "First name must not be blank")
    private String firstName;

    private String middleName;

    @NotBlank(message = "Last name must not be blank")
    private String lastName;

    @URL(message = "Profile image must be valid")
    @NotBlank(message = "Profile image must not be blank")
    private String profileImage;

    @Pattern(regexp = "^[0-9]*$", message = "Only number allowed")
    @NotBlank(message = "Phone number must not be blank")
    @Size(min = 10, max = 10, message = "Phone number must be 10 digits")
    private String phone;

    @NotBlank(message = "Address must not be blank")
    private String address;

    @NotNull(message = "Birth day must not be null")
    private Date birthDay;

    @Pattern(regexp = "^[0-9]*$", message = "Only number allowed")
    @NotBlank(message = "ID Card must not be blank")
    @Size(min = 12, max = 12, message = "ID Card must be 12 digits")
    private String idCard;

    @NotNull(message = "Gender must not be null")
    private boolean gender;

    @ManyToOne
    @JoinColumn(name = "major_id")
    private Major major;

    private boolean status = true;

    @ManyToOne
    private Campus campus;

    private LocalDateTime createAt = LocalDateTime.now();

    private LocalDateTime updateAt = LocalDateTime.now();

    public Student(UUID studentId) {
        this.id = studentId;
    }


    public Student(String email, String studentCode, String username, String firstName, String middleName, String lastName, String profileImage, String phone, String address, Date birthDay, String idCard, boolean gender, LocalDateTime createAt, LocalDateTime updateAt, boolean status, UUID majorId, Long campusId) {
        this.email = email;
        this.studentCode = studentCode;
        this.username = username;
        this.firstName = firstName;
        this.middleName = middleName;
        this.lastName = lastName;
        this.profileImage = profileImage;
        this.phone = phone;
        this.address = address;
        this.birthDay = birthDay;
        this.idCard = idCard;
        this.gender = gender;
        this.createAt = createAt;
        this.updateAt = updateAt;
        this.status = status;
        this.major = new Major(majorId);
        this.campus = new Campus(campusId);
    }
}
