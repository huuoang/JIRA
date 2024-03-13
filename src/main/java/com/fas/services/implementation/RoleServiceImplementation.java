package com.fas.services.implementation;

import com.fas.models.dtos.responses.RoleResponseDTO;
import com.fas.models.entities.Role;
import com.fas.models.enums.RoleType;
import com.fas.models.exceptions.RoleExceptions;
import com.fas.repositories.RoleRepository;
import com.fas.services.RoleSevice;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class RoleServiceImplementation implements RoleSevice {
    @Autowired
    private RoleRepository roleRepository;

    /**
     * Find a role by type.
     *
     * @param  roleType   the type of the role to find
     * @return           the role found by the type
     */
    @Override
    public Role findRoleByType(RoleType roleType) {
        Optional<Role> role = roleRepository.findByType(roleType);
        if(role.isEmpty()) {
            throw new RoleExceptions("Role not found");
        }
        return role.get();
    }

    /**
     * Find all roles and map them to RoleResponseDTOs.
     *
     * @return          list of RoleResponseDTOs
     */
    public List<RoleResponseDTO> findAllRoles() {
        List<Role> roles = roleRepository.findAll();
        return roles.stream().map(role -> new RoleResponseDTO(role)).toList();
    }

    /**
     * Finds a role by its ID.
     *
     * @param  id  the ID of the role to find
     * @return     the role with the given ID
     */
    public Role findRoleById(Long id) {
        Optional<Role> role = roleRepository.findById(id);
        if(role.isEmpty()) {
            throw new RoleExceptions("Role not found");
        }
        return role.get();
    }
}
