package com.fas.services.implementation;

import com.fas.models.dtos.requests.AccountRequestDTO;
import com.fas.models.dtos.requests.StudentRequestDTO;
import com.fas.models.dtos.responses.StudentResponseDTO;
import com.fas.models.entities.Student;
import com.fas.models.exceptions.StudentExceptions;
import com.fas.repositories.AccountRepository;
import com.fas.repositories.StudentRepository;
import com.fas.services.AccountService;
import com.fas.services.StudentService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
public class StudentServiceImplementation implements StudentService {
    @Autowired
    private StudentRepository studentRepository;

    @Autowired
    private AccountRepository accountRepository;

    @Autowired
    private AccountService accountService;

    @Override
    public StudentResponseDTO createStudent(StudentRequestDTO student) throws StudentExceptions {
        System.out.println(student);
        if (accountRepository.findByEmail(student.getEmail()) != null) {
            throw new StudentExceptions("Email already exists");
        }

        if(studentRepository.findByPhone(student.getPhone()) != null){
            throw new StudentExceptions("Phone already exists");
        }

        if(studentRepository.findByIDCard(student.getIdCard()) != null){
            throw new StudentExceptions("IDCard already exists");
        }
        Student newStudent = student.getStudent();
        Student savedStudent = studentRepository.save(newStudent);

        AccountRequestDTO accountRequestDTO = new AccountRequestDTO(savedStudent.getEmail(), "123456", 2, 1, null, null, savedStudent.getId());
        accountService.createAccount(accountRequestDTO);

        return new StudentResponseDTO(savedStudent);
    }

    @Override
    public Student findStudentById(UUID studentId) throws StudentExceptions {
        Optional<Student> existedStudent = studentRepository.findById(studentId);
        if(existedStudent.isEmpty()){
            throw new StudentExceptions("Student not found");
        }
        return existedStudent.get();
    }


    @Override
    public StudentResponseDTO updateStudent(UUID studentId, StudentRequestDTO student) throws StudentExceptions {
        Student oldStudent = findStudentById(studentId);

        if(!oldStudent.isStatus()) {
            throw new StudentExceptions("Not available to update");
        }

        Student newStudent = student.getStudent();
        if(studentRepository.findByPhoneUpdate(newStudent.getPhone(), studentId) != null) {
            throw new StudentExceptions("Phone already exists");
        }
        if(studentRepository.findByIDCardUpdate(newStudent.getIdCard(), studentId) != null) {
            throw new StudentExceptions("ID Card already exists");
        }
        if(newStudent.getEmail() != null){
            oldStudent.setEmail(newStudent.getEmail());
        }
        if(newStudent.getUsername() != null){
            oldStudent.setUsername(newStudent.getUsername());
        }
        if(newStudent.getFirstName() != null){
            oldStudent.setFirstName(newStudent.getFirstName());
        }
        if(newStudent.getMiddleName() != null){
            oldStudent.setMiddleName(newStudent.getMiddleName());
        }
        if(newStudent.getLastName() != null){
            oldStudent.setLastName(newStudent.getLastName());
        }
        if(newStudent.getProfileImage() != null){
            oldStudent.setProfileImage(newStudent.getProfileImage());
        }
        if(newStudent.getPhone() != null){
            oldStudent.setPhone(newStudent.getPhone());
        }
        if(newStudent.getAddress() != null){
            oldStudent.setAddress(newStudent.getAddress());
        }
        if(newStudent.getBirthDay() != null){
            oldStudent.setBirthDay(newStudent.getBirthDay());
        }
        if(newStudent.getMajor() != null){
            oldStudent.setMajor(newStudent.getMajor());
        }
        if(newStudent.getCampus() != null){
            oldStudent.setCampus(newStudent.getCampus());
        }
        if(newStudent.isGender() != oldStudent.isGender()){
            oldStudent.setGender(newStudent.isGender());
        }
        if(newStudent.getIdCard() != null){
            oldStudent.setIdCard(newStudent.getIdCard());
        }

        oldStudent.setUpdateAt(LocalDateTime.now());

        Student savedStudent = studentRepository.save(oldStudent);
        StudentResponseDTO studentResponseDTO = new StudentResponseDTO(savedStudent);
        return studentResponseDTO;
    }

    @Override
    public StudentResponseDTO deleteStudent(UUID studentId) throws StudentExceptions {
        Student oldStudent = findStudentById(studentId);

        oldStudent.setUpdateAt(LocalDateTime.now());
        oldStudent.setStatus(!oldStudent.isStatus());
        Student updateStudent = studentRepository.save(oldStudent);

        StudentResponseDTO studentResponseDTO = new StudentResponseDTO(updateStudent);
        return studentResponseDTO;
    }



    @Override
    public List<StudentResponseDTO> getAllStudents() {
        List<Student> students = studentRepository.findAll();
        List<StudentResponseDTO> studentResponseDTOS = new ArrayList<>();
        for (Student student : students) {
            StudentResponseDTO studentResponseDTO = new StudentResponseDTO(student);
            studentResponseDTOS.add(studentResponseDTO);
        }
        return studentResponseDTOS;
    }

    @Override
    public Student findStudentByEmail(String email) {
        Student student = studentRepository.findByEmail(email);
        return student;
    }
}
