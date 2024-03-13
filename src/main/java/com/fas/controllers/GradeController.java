package com.fas.controllers;

import com.fas.models.dtos.requests.GradeRequestDTO;
import com.fas.models.dtos.responses.GradeResponseDTO;
import com.fas.models.enums.Code;
import com.fas.models.utils.MessageDetails;
import com.fas.services.GradeService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
public class GradeController {
    @Autowired
    private GradeService gradeService;

    @PostMapping("/grade")
    private MessageDetails<GradeResponseDTO> createGrade(@RequestBody @Valid GradeRequestDTO gradeReq) {
        GradeResponseDTO grade = gradeService.createGrade(gradeReq);
        if(grade == null) {
            return new MessageDetails<GradeResponseDTO>("Create grade failed", null, Code.FAILURE);
        }
        return new MessageDetails<GradeResponseDTO>("Grade created successfully", grade, Code.SUCCESS);
    }

    @GetMapping("/grade")
    private MessageDetails<List<GradeResponseDTO>> getAllGrade() {
        List<GradeResponseDTO> courses = gradeService.getAllGrade();
        if(courses == null) {
            return new MessageDetails<List<GradeResponseDTO>>("Get all grade failed", null, Code.FAILURE);
        }
        return new MessageDetails<List<GradeResponseDTO>>("Get all grade successfully", courses, Code.SUCCESS);
    }

    @PutMapping("/grade/update/{gradeId}")
    private MessageDetails<GradeResponseDTO> updateCourse(@RequestBody GradeRequestDTO gradeReq, @PathVariable UUID gradeId) {
        GradeResponseDTO course = gradeService.updateGrade(gradeId, gradeReq);
        if(course == null) {
            return new MessageDetails<GradeResponseDTO>("Update grade failed", null, Code.FAILURE);
        }
        return new MessageDetails<GradeResponseDTO>("Update Grade successfully", course, Code.SUCCESS);
    }

    @PutMapping("/grade/delete/{gradeId}")
    private MessageDetails<GradeResponseDTO> deleteCourse(@PathVariable UUID gradeId) {
        GradeResponseDTO course = gradeService.deleteGrade(gradeId);
        if(course == null) {
            return new MessageDetails<GradeResponseDTO>("Delete grade failed", null, Code.FAILURE);
        }
        return new MessageDetails<GradeResponseDTO>("Delete grade successfully", course, Code.SUCCESS);
    }

    @PutMapping("/grade/{gradeId}/assign/{studentId}")
    private MessageDetails<GradeResponseDTO> assignCourse(@PathVariable UUID gradeId, @PathVariable UUID studentId) {
        GradeResponseDTO course = gradeService.assignGradeToStudent(gradeId, studentId);
        if(course == null) {
            return new MessageDetails<GradeResponseDTO>("Assign course failed", null, Code.FAILURE);
        }
        return new MessageDetails<GradeResponseDTO>("Assign course successfully", course, Code.SUCCESS);

    }

    @PutMapping("/grade/{gradeId}/unassign/{studentId}")
    public MessageDetails<GradeResponseDTO> unassignCourse(@PathVariable UUID gradeId, @PathVariable UUID studentId) {
        GradeResponseDTO course = gradeService.unassignGradeToStudent(gradeId, studentId);
        if(course == null) {
            return new MessageDetails<GradeResponseDTO>("Unassign course failed", null, Code.FAILURE);
        }
        return new MessageDetails<GradeResponseDTO>("Unassign course successfully", course, Code.SUCCESS);
    }
}
