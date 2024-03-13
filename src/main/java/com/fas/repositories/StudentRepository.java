package com.fas.repositories;

import com.fas.models.entities.Student;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface StudentRepository extends JpaRepository<Student, UUID> {

    Student findByEmail(String email);

    @Query("SELECT s FROM Student s WHERE s.phone = :phone")
    Student findByPhone(@Param("phone") String phone);

    @Query("SELECT s FROM Student s WHERE s.phone = :phone AND s.id != :id")
    Student findByPhoneUpdate(@Param("phone") String phone, @Param("id") UUID id);

    @Query("SELECT s FROM Student s WHERE s.idCard = :IDCard")
    Student findByIDCard(@Param("IDCard") String IDCard);

    @Query("SELECT s FROM Student s WHERE s.idCard = :IDCard AND s.id != :id")
    Student findByIDCardUpdate(@Param("IDCard") String IDCard, @Param("id") UUID id);
}
