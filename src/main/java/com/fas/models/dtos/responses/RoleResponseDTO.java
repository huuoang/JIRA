package com.fas.models.dtos.responses;

import com.fas.models.entities.Role;
import com.fas.models.enums.RoleType;
import lombok.Data;

@Data
public class RoleResponseDTO {
    private Long id;

    private RoleType type;

    private String name;

    public RoleResponseDTO(Role role) {
        this.id = role.getId();
        this.type = role.getType();
        this.name = role.getName();
    }
}
