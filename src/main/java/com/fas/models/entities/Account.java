package com.fas.models.entities;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Account {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;

    @Pattern(regexp = "^[\\w!#$%&'*+/=?`{|}~^-]+@fpt\\.edu\\.vn$", message = "Email must be valid")
    private String email;

    @NotBlank(message = "Password must not be blank")
    private String password;

    @ManyToOne
    @JoinColumn(name = "role_id")
    @NotNull(message = "Role must not be null")
    private Role role;

    @ManyToOne
    @JoinColumn(name = "campus_id")
    @NotNull(message = "Campus must not be null")
    private Campus campus;

    @OneToOne
    private Instructor instructor;

    @OneToOne
    private SystemUser systemUser;

    @OneToOne
    private Student student;

    private LocalDateTime createAt = LocalDateTime.now();

    private LocalDateTime updateAt = LocalDateTime.now();

    public Account(String email, long campusId) {
        this.email = email;
        this.campus = new Campus(campusId);
    }

    public Account(String email, String password, long roleId, long campusId, UUID instructorId, UUID systemUserId, UUID studentId) {
        this.email = email;
        this.password = password;
        this.role = new Role(roleId);
        this.campus = new Campus(campusId);
        this.instructor = instructorId == null ? null : new Instructor(instructorId);
        this.systemUser = systemUserId == null ? null : new SystemUser(systemUserId);
        this.student = studentId == null ? null : new Student(studentId);
    }
}
