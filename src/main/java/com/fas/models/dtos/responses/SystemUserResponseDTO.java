package com.fas.models.dtos.responses;

import com.fas.models.entities.SystemUser;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.UUID;

@Data
public class SystemUserResponseDTO {
    private UUID id;

    private String email;

    private boolean status;

    private String username;

    private LocalDateTime createAt = LocalDateTime.now();

    private LocalDateTime updateAt = LocalDateTime.now();

    public SystemUserResponseDTO(SystemUser systemUser) {
        this.id = systemUser.getId();
        this.email = systemUser.getEmail();
        this.status = systemUser.isStatus();
        this.username = systemUser.getUsername();
        this.createAt = systemUser.getCreateAt();
        this.updateAt = systemUser.getUpdateAt();
    }
}
