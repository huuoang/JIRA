package com.fas.services.implementation;

import com.fas.models.dtos.requests.CourseRequestDTO;
import com.fas.models.dtos.responses.CourseResponseDTO;
import com.fas.models.entities.Course;
import com.fas.models.entities.Major;
import com.fas.models.exceptions.CourseExceptions;
import com.fas.models.exceptions.StudentExceptions;
import com.fas.repositories.CourseRepository;
import com.fas.services.CourseService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;


@Service
public class CourseServiceImplementation implements CourseService {

    @Autowired
    private CourseRepository courseRepository;

    /**
     * Creates a major using the provided course request.
     *
     * @param  courseRequest   the course request containing the course information
     * @return                 the response DTO containing the newly created course
     */
    @Override
    public CourseResponseDTO creatCourse(CourseRequestDTO courseRequest) {
        Course course = courseRequest.getCourse();
        Course checkCourse = courseRepository.findByCode(course.getCode());
        if (checkCourse != null) {
            throw new CourseExceptions("Course already exists");
        }
        Course newCourse = courseRepository.save(course);
        return new CourseResponseDTO(newCourse);
    }

    /**
     * Updates the major course with the provided information and returns the updated course response DTO.
     *
     * @param  courseRequest	description of the course request DTO
     * @param  id	description of the UUID for the major course
     * @return         	description of the updated course response DTO
     */
    @Override
    public CourseResponseDTO updateCourse(CourseRequestDTO courseRequest, UUID id) {
        Course existedCourse = getCourseById(id);
        if(!existedCourse.isStatus()) {
            throw new CourseExceptions("Not available to update");
        }

        Course newCourse = courseRequest.getCourse();
        Course checkCourse = courseRepository.findByUniqueCode(newCourse.getCode(), id);

        if (checkCourse != null) {
            throw new CourseExceptions("Course already exists");
        }

        existedCourse.setCode(newCourse.getCode());
        existedCourse.setName(newCourse.getName());
        existedCourse.setUpdatedAt(LocalDateTime.now());
        existedCourse.setDescription(newCourse.getDescription());
        existedCourse.setNoCredit(newCourse.getNoCredit());

        Course savedCourse = courseRepository.save(existedCourse);
        return new CourseResponseDTO(savedCourse);
    }

    /**
     * Deletes a major by ID and returns the corresponding response DTO.
     *
     * @param  id  The UUID of the major to be deleted
     * @return     The response DTO of the deleted major
     */
    @Override
    public CourseResponseDTO deleteCourse(UUID id) {
        Course existedCourse = getCourseById(id);

        existedCourse.setUpdatedAt(LocalDateTime.now());
        existedCourse.setStatus(!existedCourse.isStatus());
        Course savedCourse = courseRepository.save(existedCourse);

        return new CourseResponseDTO(savedCourse);
    }

    /**
     * Retrieves a major course by its ID.
     *
     * @param  id  the UUID of the major course
     * @return     the major course with the given ID
     */
    @Override
    public Course getCourseById(UUID id) {
        Optional<Course> course = courseRepository.findById(id);
        if(course.isEmpty()) {
            throw new CourseExceptions("Course not found");
        }
        return course.get();
    }

    /**
     * Retrieves all courses and converts them to response DTOs.
     *
     * @return         list of CourseResponseDTOs
     */
    @Override
    public List<CourseResponseDTO> getAllCourse() {
        List<Course> courses = courseRepository.findAll();
        List<CourseResponseDTO> listCourse = new ArrayList<>();
        for(Course course : courses) {
            CourseResponseDTO courseResponseDTO = new CourseResponseDTO(course);
            listCourse.add(courseResponseDTO);
        }
        return listCourse;
    }

    /**
     * Retrieves a course by its code.
     *
     * @param  code  the code of the course to retrieve
     * @return      the course with the specified code
     */
    @Override
    public Course getCourseByCode(String code) {
        Course course = courseRepository.findByCode(code);
        return course;
    }
}
