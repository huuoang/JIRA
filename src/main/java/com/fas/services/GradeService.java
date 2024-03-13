package com.fas.services;

import com.fas.models.dtos.requests.GradeRequestDTO;
import com.fas.models.dtos.responses.GradeResponseDTO;
import com.fas.models.entities.Grade;

import java.util.List;
import java.util.UUID;

public interface GradeService {
    public GradeResponseDTO createGrade(GradeRequestDTO gradeRequestDTO);

    public GradeResponseDTO updateGrade(UUID id, GradeRequestDTO gradeRequestDTO);

    public GradeResponseDTO deleteGrade(UUID id);

    public List<GradeResponseDTO> getAllGrade();

    public Grade getGradeById(UUID id);

    public Grade getGradeByCode(String code);

    public GradeResponseDTO assignGradeToStudent(UUID gradeId, UUID studentId);

    public GradeResponseDTO unassignGradeToStudent(UUID gradeId, UUID studentId);

}
