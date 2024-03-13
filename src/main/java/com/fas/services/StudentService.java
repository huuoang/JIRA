package com.fas.services;

import com.fas.models.dtos.requests.StudentRequestDTO;
import com.fas.models.dtos.responses.StudentResponseDTO;
import com.fas.models.entities.Student;
import com.fas.models.exceptions.StudentExceptions;

import java.util.List;
import java.util.UUID;

public interface StudentService {

    public StudentResponseDTO createStudent(StudentRequestDTO student) throws StudentExceptions;

    public Student findStudentById(UUID studentId) throws StudentExceptions;

    public StudentResponseDTO updateStudent(UUID studentId, StudentRequestDTO student) throws StudentExceptions;

    public StudentResponseDTO deleteStudent(UUID studentId) throws StudentExceptions;

    public List<StudentResponseDTO> getAllStudents();

    public Student findStudentByEmail(String email);
}
