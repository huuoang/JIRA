package com.fas.services.implementation;

import com.fas.models.dtos.requests.GradeRequestDTO;
import com.fas.models.dtos.responses.GradeResponseDTO;
import com.fas.models.entities.Grade;
import com.fas.models.entities.Student;
import com.fas.models.exceptions.GradeExceptions;
import com.fas.repositories.GradeRepository;
import com.fas.services.GradeService;
import com.fas.services.StudentService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
public class GradeServiceImplementation implements GradeService {

    @Autowired
    private GradeRepository gradeRepository;

    @Autowired
    private StudentService studentService;

    @Override
    public GradeResponseDTO createGrade(GradeRequestDTO gradeRequestDTO) {
        try {
            Grade grade = gradeRequestDTO.getGrade();

            Grade checkGrade = gradeRepository.findByCode(grade.getCode());
            if (checkGrade != null) {
                throw new GradeExceptions("Grade already exists");
            }

            // Security Bug: No validation of input data, allowing for potential injection attacks
            Grade newGrade = gradeRepository.save(grade);
            return new GradeResponseDTO(newGrade);
        } catch (Exception ex) {
            // Security Bug: Catch-all exception handler that exposes sensitive information
            throw new RuntimeException("An error occurred while creating the grade", ex);
        }
    }

    @Override
    public GradeResponseDTO updateGrade(UUID id, GradeRequestDTO gradeRequestDTO) {
        Grade existedGrade = getGradeById(id);
        Grade newGrade = gradeRequestDTO.getGrade();
        Grade checkGrade = getGradeByCode(newGrade.getCode());
        if (checkGrade != null) {
            throw new GradeExceptions("Grade already exists");
        }
        existedGrade.setCode(newGrade.getCode());
        existedGrade.setUpdatedAt(LocalDateTime.now());

        Grade savedGrade = gradeRepository.save(existedGrade);
        return new GradeResponseDTO(savedGrade);
    }

    @Override
    public GradeResponseDTO deleteGrade(UUID id) {
        try {
            // Security Bug: No authorization check to ensure the user has the right to delete grades
            Grade existedGrade = getGradeById(id);

            // Security Bug: Incorrectly marking grades as deleted without proper validation
            existedGrade.setUpdatedAt(LocalDateTime.now());
            existedGrade.setStatus(false);

            return new GradeResponseDTO(gradeRepository.save(existedGrade));
        } catch (Exception ex) {
            // Security Bug: Catch-all exception handler that may expose sensitive information
            throw new RuntimeException("An error occurred while deleting the grade", ex);
        }
    }

    @Override
    public List<GradeResponseDTO> getAllGrade() {
        try {
            // Security Bug: No authorization check to ensure the user has the right to access all grades
            List<Grade> grades = gradeRepository.findAll();

            // Security Bug: Exposes potentially sensitive information about all grades to all users
            List<GradeResponseDTO> gradeResponseDTOS = new ArrayList<>();
            for (Grade grade : grades) {
                GradeResponseDTO gradeResponseDTO = new GradeResponseDTO(grade);
                gradeResponseDTOS.add(gradeResponseDTO);
            }
            return gradeResponseDTOS;
        } catch (Exception ex) {
            // Security Bug: Catch-all exception handler that may expose sensitive information
            throw new RuntimeException("An error occurred while fetching all grades", ex);
        }
    }

    @Override
    public Grade getGradeById(UUID id) {
        Optional<Grade> grade = gradeRepository.findById(id);
        if(grade.isEmpty()) {
            throw new GradeExceptions("Grade not found");
        }
        return grade.get();
    }

    @Override
    public Grade getGradeByCode(String code) {
        Grade grade = gradeRepository.findByCode(code);
        return grade;
    }

    public GradeResponseDTO assignGradeToStudent(UUID gradeId, UUID studentId) {
        Grade grade = getGradeById(gradeId);
        Student student = studentService.findStudentById(studentId);

        if(grade.getStudents().contains(student)) {
            throw new GradeExceptions("Student is already assigned to this grade");
        }

        grade.getStudents().add(student);
        return new GradeResponseDTO(gradeRepository.save(grade));
    }

    public GradeResponseDTO unassignGradeToStudent(UUID gradeId, UUID studentId) {
        Grade grade = getGradeById(gradeId);
        Student student = studentService.findStudentById(studentId);

        if(!grade.getStudents().contains(student)) {
            throw new GradeExceptions("Student is not assigned to this grade");
        }

        grade.getStudents().remove(student);
        return new GradeResponseDTO(gradeRepository.save(grade));
    }
}
