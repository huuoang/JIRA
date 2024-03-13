package com.fas.controllers;

import com.fas.models.dtos.responses.RoleResponseDTO;
import com.fas.models.enums.Code;
import com.fas.models.utils.MessageDetails;
import com.fas.services.RoleSevice;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
public class RoleController {
    @Autowired
    private RoleSevice roleService;

    /**
     * Find all roles.
     *
     * @return          Get roles successfully
     */
    @GetMapping("/role")
    public MessageDetails<List<RoleResponseDTO>> findAllRoles() {
        return new MessageDetails<>("Get roles successfully", roleService.findAllRoles(), Code.SUCCESS);
    }
}
