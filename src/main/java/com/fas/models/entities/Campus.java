package com.fas.models.entities;

import com.fas.models.enums.CampusName;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Campus {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    @Enumerated(EnumType.STRING)
    private CampusName name;

    private String location;

    private LocalDateTime createAt = LocalDateTime.now();

    private LocalDateTime updateAt = LocalDateTime.now();

    public Campus(Long id, CampusName name) {
        this.id = id;
        this.name = name;
    }

    public Campus(long campusId) {
        this.id = campusId;
    }
}
