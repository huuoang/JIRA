package com.fas.services;

import com.fas.models.dtos.requests.InstructorRequestDTO;
import com.fas.models.dtos.requests.StudentRequestDTO;
import com.fas.models.dtos.responses.InstructorResponseDTO;
import com.fas.models.dtos.responses.StudentResponseDTO;
import com.fas.models.entities.Instructor;
import com.fas.models.entities.Student;
import com.fas.models.exceptions.InstructorExceptions;
import com.fas.models.exceptions.StudentExceptions;

import java.util.List;
import java.util.UUID;

public interface InstructorService {
    public InstructorResponseDTO createInstructor(InstructorRequestDTO instructor) throws InstructorExceptions;

    public Instructor findInstructorByEmail(String email) throws InstructorExceptions;

    public Instructor findInstructorById(UUID instructorId) throws InstructorExceptions;

    public InstructorResponseDTO updateInstructor(UUID instructorId, InstructorRequestDTO instructorRequest) throws InstructorExceptions;

    public InstructorResponseDTO deleteInstructor(UUID instructorId) throws InstructorExceptions;

    public List<InstructorResponseDTO> getAllInstructors() throws InstructorExceptions;
}
