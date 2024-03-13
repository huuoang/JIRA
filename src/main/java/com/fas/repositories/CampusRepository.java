package com.fas.repositories;

import com.fas.models.entities.Campus;
import com.fas.models.enums.CampusName;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface CampusRepository extends JpaRepository<Campus, Long> {
    Optional<Campus> findByName(CampusName name);
}
