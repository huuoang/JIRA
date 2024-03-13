package com.fas.services;

import com.fas.models.dtos.requests.CourseRequestDTO;
import com.fas.models.dtos.requests.MajorRequestDTO;
import com.fas.models.dtos.responses.CourseResponseDTO;
import com.fas.models.entities.Course;

import java.util.List;
import java.util.UUID;

public interface CourseService {
    public CourseResponseDTO creatCourse(CourseRequestDTO courseRequest);

    public CourseResponseDTO updateCourse(CourseRequestDTO courseRequest, UUID id);

    public CourseResponseDTO deleteCourse(UUID id);

    public Course getCourseById(UUID id);

    public List<CourseResponseDTO> getAllCourse();

    public Course getCourseByCode(String code);
}
