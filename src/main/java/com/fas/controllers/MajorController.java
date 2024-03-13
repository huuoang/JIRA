package com.fas.controllers;


import com.fas.models.dtos.requests.MajorRequestDTO;
import com.fas.models.dtos.responses.MajorResponseDTO;
import com.fas.models.dtos.responses.StudentResponseDTO;
import com.fas.models.entities.Major;
import com.fas.models.entities.Student;
import com.fas.models.enums.Code;
import com.fas.models.utils.MessageDetails;
import com.fas.services.MajorService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
public class MajorController {

    @Autowired
    private MajorService majorService;

    /**
     * Create a major using the provided MajorRequestDTO.
     *
     * @param  majorReq  the MajorRequestDTO object for creating a major
     * @return           the message details with the created MajorResponseDTO and success code
     */
    @PostMapping("/major")
    private MessageDetails<MajorResponseDTO>  createMajor(@RequestBody @Valid MajorRequestDTO majorReq) {
        MajorResponseDTO major = majorService.createMajor(majorReq);
        return new MessageDetails<MajorResponseDTO>("Major created successfully", major, Code.SUCCESS);
    }

    @GetMapping("/major/{majorId}")
    private MessageDetails<MajorResponseDTO> getMajorById(@PathVariable UUID majorId) {
        Major major = majorService.getMajorById(majorId);
        if(major == null) {
            return new MessageDetails<>("Get major failed", null, Code.FAILURE);
        }
        return new MessageDetails<>("Get major successfully", new MajorResponseDTO(major), Code.SUCCESS);
    }

    /**
     * Get all major details.
     *
     * @return         	description of return value
     */
    @GetMapping("/major")
    private MessageDetails<List<MajorResponseDTO>> getAllMajor() {
        List<MajorResponseDTO> majors = majorService.getAllMajors();
        return new MessageDetails<List<MajorResponseDTO>>("Get all majors successfully", majors, Code.SUCCESS);
    }

    /**
     * Update a major with the given major ID.
     *
     * @param  major     the MajorRequestDTO containing the updated major information
     * @param  majorId   the UUID of the major to be updated
     * @return          a MessageDetails containing the updated MajorResponseDTO
     */
    @PutMapping("/major/update/{majorId}")
    private MessageDetails<MajorResponseDTO> updateMajor(@RequestBody MajorRequestDTO major,@PathVariable  UUID majorId) {
        MajorResponseDTO majorResponseDTO = majorService.updateMajor(major, majorId);
        return new MessageDetails<MajorResponseDTO>("Update major successfully", majorResponseDTO, Code.SUCCESS);
    }

    /**
     * Deletes a major by ID.
     *
     * @param  majorId   the ID of the major to be deleted
     * @return          a message details object with the result of the delete operation
     */
    @PutMapping("/major/delete/{majorId}")
    private MessageDetails<MajorResponseDTO> deleteMajor(@PathVariable UUID majorId) {
        MajorResponseDTO major =  majorService.deleteMajor(majorId);
        if(major == null) {
            return new MessageDetails<MajorResponseDTO>("Delete major failed", null, Code.FAILURE);
        }
        return new MessageDetails<MajorResponseDTO>("Delete major successfully", major, Code.SUCCESS);
    }
}
