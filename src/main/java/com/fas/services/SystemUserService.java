package com.fas.services;

import com.fas.models.dtos.requests.SystemUserRequestDTO;
import com.fas.models.dtos.responses.SystemUserResponseDTO;
import com.fas.models.entities.SystemUser;

import java.util.List;
import java.util.UUID;

public interface SystemUserService {
    public SystemUserResponseDTO createSystemUser(SystemUserRequestDTO systemUser);

    public SystemUserResponseDTO updateSystemUser(UUID systemUserId, SystemUserRequestDTO systemUser);

    public SystemUser getSystemUserByEmail(String email);

    public SystemUserResponseDTO deleteSystemUser(UUID systemUserId);

    public List<SystemUserResponseDTO> getAllSystemUsers();

    public SystemUser getSystemUserById(UUID systemUserId);
}
