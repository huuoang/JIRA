package com.fas.controllers;

import com.fas.models.dtos.responses.CampusResponseDTO;
import com.fas.models.enums.Code;
import com.fas.models.utils.MessageDetails;
import com.fas.services.CampusService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
public class CampusController {
    @Autowired
    private CampusService campusService;

    /**
     * Find all campuses.
     *
     * @return Get campuses successfully
     */
    @GetMapping("/campus")
    public MessageDetails<List<CampusResponseDTO>> findAllCampuses() {
        return new MessageDetails<>("Get campuses successfully", campusService.findAllCampuses(), Code.SUCCESS);
    }
}
