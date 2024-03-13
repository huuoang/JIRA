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
public class Instructor {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;

    @Pattern(regexp = "^[\\w!#$%&'*+/=?`{|}~^-]+@fpt\\.edu\\.vn$", message = "Email must be valid")
    private String email;

    @NotBlank(message = "Username must not be blank")
    private String username;

    @NotBlank(message = "First name must not be blank")
    private String firstName;

    private String middleName;

    @NotBlank(message = "Last name must not be blank")
    private String lastName;

    @URL(message = "Profile image must be valid")
    private String profileImage;

    @NotBlank(message = "Phone number must not be blank")
    @Size(min = 10, max = 10, message = "Phone number must be 10 digits")
    private String phone;

    @NotBlank(message = "Address must not be blank")
    private String address;

    @NotNull(message = "Birth day must not be null")
    private Date birthDay;

    @Pattern(regexp = "\\d", message = "Only number allowed")
    @NotBlank(message = "ID Card must not be blank")
    @Size(min = 12, max = 12, message = "ID Card must be 12 digits")
    private String idCard;

    @NotNull(message = "Gender must not be null")
    private boolean gender;

    private boolean status = true;

    @ManyToOne
    @NotNull(message = "Campus must not be null")
    @JoinColumn(name = "campus_id")
    private Campus campus;

    private LocalDateTime createAt = LocalDateTime.now();

    private LocalDateTime updateAt = LocalDateTime.now();

    public Instructor(UUID instructorId) {
        this.id = instructorId;
    }

    public Instructor(String email, String username, String firstName, String middleName, String lastName, String profileImage, String phone, String address, Date birthDay, String idCard, Long campusId, boolean gender, boolean status, LocalDateTime createAt, LocalDateTime updateAt) {
        this.email = email;
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
        this.status = status;
        this.campus = new Campus(campusId);
        this.createAt = createAt;
        this.updateAt = updateAt;
    }
}
