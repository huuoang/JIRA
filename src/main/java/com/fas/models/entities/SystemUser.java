package com.fas.models.entities;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
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
public class SystemUser {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;

    @Email(message = "Email must be valid")
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

    @NotBlank(message = "Birth day must not be blank")
    private Date birthDay;

    private boolean status = true;

    private LocalDateTime createAt = LocalDateTime.now();

    private LocalDateTime updateAt = LocalDateTime.now();

    @OneToOne
    private Account account;

    public SystemUser(String email, String username, String firstName, String middleName, String lastName, String profileImage, String phone, String address, Date birthDay) {
        this.email = email;
        this.username = username;
        this.firstName = firstName;
        this.middleName = middleName;
        this.lastName = lastName;
        this.profileImage = profileImage;
        this.phone = phone;
        this.address = address;
        this.birthDay = birthDay;
    }

    public SystemUser(UUID systemUserId) {
        this.id = systemUserId;
    }
}