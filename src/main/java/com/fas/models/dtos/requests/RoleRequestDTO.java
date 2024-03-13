package com.fas.models.dtos.requests;

import com.fas.models.entities.Role;
import com.fas.models.enums.RoleType;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import lombok.Data;

@Data
public class RoleRequestDTO {
    private Long id;

    private RoleType type;

    public Role getRole() {
        return new Role(id, type);
    }
}
