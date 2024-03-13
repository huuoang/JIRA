package com.fas.repositories;

import com.fas.models.entities.Instructor;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.UUID;

public interface InstructorRepository extends JpaRepository<Instructor, UUID> {

    Instructor findByEmail(String email);

    Instructor findByPhone(String phone);

    @Query("SELECT i FROM Instructor i WHERE i.phone = :phone AND i.id != :id")
    Instructor findByUniquePhone(@Param("phone") String phone, @Param("id") UUID id);

    Instructor findByIdCard(String idCard);

    @Query("SELECT i FROM Instructor i WHERE i.idCard = :idCard AND i.id != :id")
    Instructor findByUniqueIdCard(@Param("idCard") String idCard, @Param("id") UUID id);
}
