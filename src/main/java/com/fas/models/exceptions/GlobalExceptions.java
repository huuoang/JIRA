package com.fas.models.exceptions;

import com.fas.models.enums.Code;
import com.fas.models.utils.ErrorObject;
import com.fas.models.utils.MessageDetails;
import jakarta.validation.ConstraintViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.context.request.WebRequest;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@ControllerAdvice
public class GlobalExceptions {

    @ExceptionHandler(ConstraintViolationException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ResponseEntity<?> handleConstraintViolationException(ConstraintViolationException ex, WebRequest request) {
        List<ErrorObject> details = new ArrayList<>();

        ex.getConstraintViolations().forEach(error -> {
            ErrorObject errorObject = new ErrorObject(error.getPropertyPath().toString(), error.getMessage());
            details.add(errorObject);
        });

        MessageDetails errorDetails = new MessageDetails("Validation Failed", details, Code.FAILURE);
        return new ResponseEntity<>(errorDetails, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ResponseEntity<?> handleMethodArgumentNotValidException(MethodArgumentNotValidException ex) {
        BindingResult bindingResult = ex.getBindingResult();

        List<ErrorObject> details = bindingResult.getFieldErrors().stream()
                .map(fieldError -> new ErrorObject(fieldError.getField(), fieldError.getDefaultMessage()))
                .collect(Collectors.toList());

        MessageDetails errorDetails = new MessageDetails("Validation Failed", details, Code.FAILURE);
        return new ResponseEntity<>(errorDetails, HttpStatus.BAD_REQUEST);
    }


    @ExceptionHandler(UsernameNotFoundException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ResponseEntity<?> handleUsernameNotFoundException(UsernameNotFoundException ex, WebRequest request) {
        MessageDetails errorDetails = new MessageDetails("Login failed", ex.getMessage(), Code.FAILURE);
        return new ResponseEntity<>(errorDetails, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(AccountExceptions.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ResponseEntity<?> handleNullPointerException(AccountExceptions ex, WebRequest request) {
        MessageDetails errorDetails = new MessageDetails("Account's information is not true", ex.getMessage(), Code.FAILURE);
        return new ResponseEntity<>(errorDetails, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(BadCredentialsException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ResponseEntity<?> handleBadCredentialsException(BadCredentialsException ex, WebRequest request) {
        MessageDetails errorDetails = new MessageDetails("Token's information is not true", ex.getMessage(), Code.FAILURE);
        return new ResponseEntity<>(errorDetails, HttpStatus.BAD_REQUEST);
    }


    @ExceptionHandler(StudentExceptions.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ResponseEntity<?> handleStudentExceptions(StudentExceptions ex, WebRequest request) {
        MessageDetails errorDetails = new MessageDetails("Error information student", ex.getMessage(), Code.FAILURE);
        return new ResponseEntity<>(errorDetails, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(RoleExceptions.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ResponseEntity<?> handleRoleExceptions(RoleExceptions ex, WebRequest request) {
        MessageDetails errorDetails = new MessageDetails("Error information role", ex.getMessage(), Code.FAILURE);
        return new ResponseEntity<>(errorDetails, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(CampusExceptions.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ResponseEntity<?> handleCampusExceptions(CampusExceptions ex, WebRequest request) {
        MessageDetails errorDetails = new MessageDetails("Error information campus", ex.getMessage(), Code.FAILURE);
        return new ResponseEntity<>(errorDetails, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(MajorExceptions.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ResponseEntity<?> handleMajorExceptions(MajorExceptions ex, WebRequest request) {
        MessageDetails errorDetails = new MessageDetails("Major information is not true", ex.getMessage(), Code.FAILURE);
        return new ResponseEntity<>(errorDetails, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(CourseExceptions.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ResponseEntity<?> handleCourseExceptions(CourseExceptions ex, WebRequest request) {
        MessageDetails errorDetails = new MessageDetails("Course information is not true", ex.getMessage(), Code.FAILURE);
        return new ResponseEntity<>(errorDetails, HttpStatus.BAD_REQUEST);
    }
    @ExceptionHandler(GradeExceptions.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ResponseEntity<?> handleGradeExceptions(GradeExceptions ex, WebRequest request) {
        MessageDetails errorDetails = new MessageDetails("Grade information is not true", ex.getMessage(), Code.FAILURE);
        return new ResponseEntity<>(errorDetails, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(SystemUserExceptions.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ResponseEntity<?> handleSystemUserExceptions(SystemUserExceptions ex, WebRequest request) {
        MessageDetails errorDetails = new MessageDetails("System user information is not true", ex.getMessage(), Code.FAILURE);
        return new ResponseEntity<>(errorDetails, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(InstructorExceptions.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ResponseEntity<?> handleInstructorExceptions(InstructorExceptions ex, WebRequest request) {
        MessageDetails errorDetails = new MessageDetails("Instructor information is not true", ex.getMessage(), Code.FAILURE);
        return new ResponseEntity<>(errorDetails, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(EventExceptions.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ResponseEntity<?> handleEventExceptions(EventExceptions ex, WebRequest request) {
        MessageDetails errorDetails = new MessageDetails("Event information is not true", ex.getMessage(), Code.FAILURE);
        return new ResponseEntity<>(errorDetails, HttpStatus.BAD_REQUEST);
    }
}
