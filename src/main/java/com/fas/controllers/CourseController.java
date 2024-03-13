package com.fas.controllers;


import com.fas.models.dtos.requests.CourseRequestDTO;
import com.fas.models.dtos.responses.CourseResponseDTO;
import com.fas.models.dtos.responses.EventResponseDTO;
import com.fas.models.entities.Course;
import com.fas.models.entities.Event;
import com.fas.models.enums.Code;
import com.fas.models.utils.MessageDetails;
import com.fas.services.CourseService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
public class CourseController {

    @Autowired
    private CourseService courseService;

    /**
     * Create a new course based on the given request.
     *
     * @param  courseReq  the validated course request
     * @return            a message details object with the created course response and success code
     */
    @PostMapping("/course")
    public MessageDetails<CourseResponseDTO> createCourse(@RequestBody @Valid CourseRequestDTO courseReq) {
        CourseResponseDTO course = courseService.creatCourse(courseReq);
        return new MessageDetails<CourseResponseDTO>("Course created successfully", course, Code.SUCCESS);
    }

    @GetMapping("/course/{courseId}")
    private MessageDetails<CourseResponseDTO> getCourseById(@PathVariable UUID courseId) {
        Course course = courseService.getCourseById(courseId);
        if(course == null) {
            return new MessageDetails<>("Get course failed", null, Code.FAILURE);
        }
        return new MessageDetails<>("Get course successfully", new CourseResponseDTO(course), Code.SUCCESS);
    }

    /**
     * Get all courses.
     *
     * @return          a message details object with a list of course response DTO
     */
    @GetMapping("/course")
    private MessageDetails<List<CourseResponseDTO>> getAllCourse() {
        List<CourseResponseDTO> courses = courseService.getAllCourse();
        return new MessageDetails<List<CourseResponseDTO>>("Get all Course successfully", courses, Code.SUCCESS);
    }

    /**
     * Update a course with the given courseId.
     *
     * @param  courseReq  the course request data
     * @param  courseId   the ID of the course to update
     * @return            details of the updated course with a success message
     */
    @PutMapping("/course/update/{courseId}")
    private MessageDetails<CourseResponseDTO> updateCourse(@RequestBody CourseRequestDTO courseReq, @PathVariable UUID courseId) {
        CourseResponseDTO course = courseService.updateCourse(courseReq, courseId);
        return new MessageDetails<CourseResponseDTO>("Update Course successfully", course, Code.SUCCESS);
    }

    /**
     * Delete a course by its ID.
     *
     * @param  courseId  the ID of the course to be deleted
     * @return          a message detailing the deletion along with the course response and status code
     */
    @PutMapping("/course/delete/{courseId}")
    private MessageDetails<CourseResponseDTO> deleteCourse(@PathVariable UUID courseId) {
        CourseResponseDTO course = courseService.deleteCourse(courseId);
        if(course == null) {
            return new MessageDetails<>("Delete Course failed", null, Code.FAILURE);
        }
        return new MessageDetails<CourseResponseDTO>("Delete Course successfully", course, Code.SUCCESS);
    }
}
