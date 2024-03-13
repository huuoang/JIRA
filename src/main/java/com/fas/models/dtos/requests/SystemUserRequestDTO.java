package com.fas.models.dtos.requests;

import com.fas.models.entities.Instructor;
import com.fas.models.entities.SystemUser;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;
import org.hibernate.validator.constraints.URL;

import java.util.Date;
import java.util.UUID;


@Data
public class SystemUserRequestDTO {

    private String email;

    private String username;

    private String firstName;

    private String middleName;

    private String lastName;

    private String profileImage;

    private String phone;

    private String address;

    private Date birthDay;

    public SystemUser getSystemUser() {
        return new SystemUser(email, username, firstName, middleName, lastName, profileImage, phone, address, birthDay);
    }

}
