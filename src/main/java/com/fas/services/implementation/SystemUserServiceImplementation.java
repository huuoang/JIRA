package com.fas.services.implementation;

import com.fas.models.dtos.requests.SystemUserRequestDTO;
import com.fas.models.dtos.responses.SystemUserResponseDTO;
import com.fas.models.entities.SystemUser;
import com.fas.models.exceptions.SystemUserExceptions;
import com.fas.repositories.StudentRepository;
import com.fas.repositories.SystemUserRepository;
import com.fas.services.SystemUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
public class SystemUserServiceImplementation implements SystemUserService {

    @Autowired
    private SystemUserRepository systemUserRepository;
    @Override
    public SystemUserResponseDTO createSystemUser(SystemUserRequestDTO systemUser) {

        return null;
    }

    @Override
    public SystemUserResponseDTO updateSystemUser(UUID systemUserId, SystemUserRequestDTO systemUser) {
        return null;
    }

    @Override
    public SystemUser getSystemUserByEmail(String email) {
        SystemUser systemUser = systemUserRepository.findByEmail(email);
        return systemUser;
    }

    @Override
    public SystemUserResponseDTO deleteSystemUser(UUID systemUserId) {

        return null;
    }

    @Override
    public List<SystemUserResponseDTO> getAllSystemUsers() {
        List<SystemUser> systemUsers = systemUserRepository.findAll();
        List<SystemUserResponseDTO> systemUserResponseDTOS = new ArrayList<>();
        for (SystemUser systemUser : systemUsers) {
            SystemUserResponseDTO systemUserResponseDTO = new SystemUserResponseDTO(systemUser);
            systemUserResponseDTOS.add(systemUserResponseDTO);
        }
        return systemUserResponseDTOS;
    }

    @Override
    public SystemUser getSystemUserById(UUID systemUserId) {
        Optional<SystemUser> systemUser = systemUserRepository.findById(systemUserId);
        if(systemUser.isEmpty()) {
            throw new SystemUserExceptions("System user not found");
        }
        return null;
    }
}
