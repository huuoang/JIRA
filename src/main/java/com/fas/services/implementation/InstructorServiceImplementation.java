package com.fas.services.implementation;

import com.fas.models.dtos.requests.AccountRequestDTO;
import com.fas.models.dtos.requests.InstructorRequestDTO;
import com.fas.models.dtos.responses.InstructorResponseDTO;
import com.fas.models.entities.Instructor;
import com.fas.models.exceptions.InstructorExceptions;
import com.fas.models.exceptions.StudentExceptions;
import com.fas.repositories.AccountRepository;
import com.fas.repositories.InstructorRepository;
import com.fas.services.AccountService;
import com.fas.services.InstructorService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
public class InstructorServiceImplementation implements InstructorService {

    @Autowired
    private InstructorRepository instructorRepository;

    @Autowired
    private AccountRepository accountRepository;

    @Autowired
    private AccountService accountService;


    @Override
    public InstructorResponseDTO createInstructor(InstructorRequestDTO instructorRequestDTO) throws InstructorExceptions {
        System.out.println(instructorRequestDTO.getIdCard());
        if (accountRepository.findByEmail(instructorRequestDTO.getEmail()) != null) {
            throw new InstructorExceptions("Email already exists");
        }

        if(instructorRepository.findByPhone(instructorRequestDTO.getPhone()) != null){
            throw new InstructorExceptions("Phone already exists");
        }

        if(instructorRepository.findByIdCard(instructorRequestDTO.getIdCard()) != null){
            throw new InstructorExceptions("IdCard already exists");
        }

        Instructor instructor = instructorRequestDTO.getIntructor();
        Instructor savedInstructor = instructorRepository.save(instructor);

        System.out.println(savedInstructor);

        AccountRequestDTO accountRequestDTO = new AccountRequestDTO(savedInstructor.getEmail(), "123456", 2, 1, savedInstructor.getId(), null, null);

        accountService.createAccount(accountRequestDTO);

        return new InstructorResponseDTO(savedInstructor);
    }

    @Override
    public Instructor findInstructorByEmail(String email) throws InstructorExceptions {
        Instructor instructor = instructorRepository.findByEmail(email);
        if (instructor == null) {
            throw new InstructorExceptions("Instructor not found with email: " + email);
        }
        return instructor;
    }

    public Instructor findInstructorById(UUID instructorId) throws InstructorExceptions {
        Optional<Instructor> instructor = instructorRepository.findById(instructorId);

        // Kiểm tra nếu instructor không tồn tại
        if (!instructor.isPresent()) {
            // Thực hiện xử lý khi instructor không tồn tại, ví dụ: ghi log và trả về giá trị mặc định hoặc ném một ngoại lệ khác
            throw new InstructorExceptions("Instructor not found with ID: " + instructorId);
        }

        return instructor.get();
    }



    @Override
    public InstructorResponseDTO updateInstructor(UUID instructorId, InstructorRequestDTO instructorRequest) throws InstructorExceptions {
        Instructor instructor = findInstructorById(instructorId);
        if(!instructor.isStatus()) {
            throw new StudentExceptions("Not available to update");
        }

        Instructor newInstructor = instructorRequest.getIntructor();

        if(instructorRepository.findByUniquePhone(newInstructor.getPhone(), instructorId) != null) {
            throw new StudentExceptions("Phone already exists");
        }
        if(instructorRepository.findByUniqueIdCard(newInstructor.getIdCard(), instructorId) != null) {
            throw new StudentExceptions("ID Card already exists");
        }

        if (newInstructor.getEmail() != null) {
            instructor.setEmail(newInstructor.getEmail());
        }
        if (newInstructor.getUsername() != null) {
            instructor.setUsername(newInstructor.getUsername());
        }
        if (newInstructor.getFirstName() != null) {
            instructor.setFirstName(newInstructor.getFirstName());
        }
        if (newInstructor.getMiddleName() != null) {
            instructor.setMiddleName(newInstructor.getMiddleName());
        }
        if (newInstructor.getLastName() != null) {
            instructor.setLastName(newInstructor.getLastName());
        }
        if (newInstructor.getProfileImage() != null) {
            instructor.setProfileImage(newInstructor.getProfileImage());
        }
        if (newInstructor.getPhone() != null) {
            instructor.setPhone(newInstructor.getPhone());
        }
        if (newInstructor.getAddress() != null) {
            instructor.setAddress(newInstructor.getAddress());
        }
        if (newInstructor.getBirthDay() != null) {
            instructor.setBirthDay(newInstructor.getBirthDay());
        }
        instructor.setUpdateAt(LocalDateTime.now());

        Instructor savedInstructor = instructorRepository.save(instructor);
        return new InstructorResponseDTO(savedInstructor);
    }

    @Override
    public InstructorResponseDTO deleteInstructor(UUID instructorId) throws InstructorExceptions {
        Instructor instructor = findInstructorById(instructorId);

        instructor.setUpdateAt(LocalDateTime.now());
        instructor.setStatus(!instructor.isStatus());

        Instructor savedInstructor = instructorRepository.save(instructor);
        return new InstructorResponseDTO(savedInstructor);
    }

    @Override
    public List<InstructorResponseDTO> getAllInstructors() throws InstructorExceptions {
        List<Instructor> listInstructors = instructorRepository.findAll();
        List<InstructorResponseDTO> newListInstructors = new ArrayList<>();
        for (Instructor instructor : listInstructors) {
            newListInstructors.add(new InstructorResponseDTO(instructor));
        }
        return newListInstructors;
    }
}
