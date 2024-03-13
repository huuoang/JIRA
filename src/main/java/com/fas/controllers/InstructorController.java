package com.fas.controllers;

import com.fas.models.dtos.requests.InstructorRequestDTO;
import com.fas.models.dtos.requests.StudentRequestDTO;
import com.fas.models.dtos.responses.InstructorResponseDTO;
import com.fas.models.dtos.responses.StudentResponseDTO;
import com.fas.models.entities.Instructor;
import com.fas.models.enums.Code;
import com.fas.models.exceptions.InstructorExceptions;
import com.fas.models.exceptions.StudentExceptions;
import com.fas.models.utils.MessageDetails;
import com.fas.services.InstructorService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
public class InstructorController {

    @Autowired
    private InstructorService instructorService;

    @PostMapping("/instructor")
    private MessageDetails<InstructorResponseDTO> createInstructor(@Valid @RequestBody InstructorRequestDTO instructorRequestDTO) throws InstructorExceptions {
        InstructorResponseDTO instructorResponseDTO = instructorService.createInstructor(instructorRequestDTO);
        if(instructorResponseDTO == null){
            return new MessageDetails<>("Create Instructor failed", null, Code.FAILURE);
        }
        return new MessageDetails<>("Instructor created successfully", instructorResponseDTO, Code.SUCCESS);
    }

    @GetMapping("/instructor")
    private MessageDetails<List<InstructorResponseDTO>> getAllInstructors() throws InstructorExceptions {
        List<InstructorResponseDTO> instructors = instructorService.getAllInstructors();
        if(instructors == null){
            return new MessageDetails<>("Get all Instructors failed", null, Code.FAILURE);
        }
        return new MessageDetails<>("Get all Instructors successfully", instructorService.getAllInstructors(), Code.SUCCESS);
    }

    @GetMapping("/instructor/{instructorId}")
    private MessageDetails<InstructorResponseDTO> getInstructorById(@PathVariable UUID instructorId) throws InstructorExceptions {
        Instructor instructor = instructorService.findInstructorById(instructorId);
        if(instructor == null){
            return new MessageDetails<>("Get Instructor failed", null, Code.FAILURE);
        }
        return new MessageDetails<>("Get Instructor successfully",new InstructorResponseDTO(instructor), Code.SUCCESS);
    }

    @PutMapping("/instructor/update/{instructorId}")
    private MessageDetails<InstructorResponseDTO> updateInstructor(@Valid @RequestBody InstructorRequestDTO instructor, @PathVariable UUID instructorId) throws InstructorExceptions {
        InstructorResponseDTO instructorResponseDTO = instructorService.updateInstructor(instructorId, instructor);
        if(instructorResponseDTO == null){
            return new MessageDetails<>("Update Instructor failed", null, Code.FAILURE);
        }
        return new MessageDetails<>("Instructor updated successfully", instructorResponseDTO, Code.SUCCESS);
    }

    @PutMapping("/instructor/delete/{instructorId}")
    private MessageDetails<InstructorResponseDTO> deleteInstructor(@PathVariable UUID instructorId) throws InstructorExceptions {
        InstructorResponseDTO instructorResponseDTO = instructorService.deleteInstructor(instructorId);
        if(instructorResponseDTO == null){
            return new MessageDetails<>("Delete Instructor failed", null, Code.FAILURE);
        }
        return new MessageDetails<>("Instructor deleted successfully", instructorResponseDTO, Code.SUCCESS);
    }
}
