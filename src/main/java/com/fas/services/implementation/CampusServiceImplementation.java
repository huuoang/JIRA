package com.fas.services.implementation;

import com.fas.models.dtos.responses.CampusResponseDTO;
import com.fas.models.entities.Campus;
import com.fas.models.enums.CampusName;
import com.fas.models.exceptions.CampusExceptions;
import com.fas.repositories.CampusRepository;
import com.fas.services.CampusService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
public class CampusServiceImplementation implements CampusService {
    @Autowired
    private CampusRepository campusRepository;

    /**
     * Finds a campus by its name.
     *
     * @param  name   the name of the campus to find
     * @return       the campus with the specified name
     */
    @Override
    public Campus findByCampusName(CampusName name) {
        Optional<Campus> campus = campusRepository.findByName(name);
        if(campus.isEmpty()) {
            throw new CampusExceptions("Campus is not existed with name: " + name);
        }
        return campus.get();
    }

    /**
     * Find all campuses and return a list of campus response DTOs.
     *
     * @return  a list of campus response DTOs
     */
    @Override
    public List<CampusResponseDTO> findAllCampuses() {
        List<Campus> campuses = campusRepository.findAll();
        List<CampusResponseDTO> campusResponseDTOS = campuses.stream().map(campus -> new CampusResponseDTO(campus)).toList();
        return campusResponseDTOS;
    }

    /**
     * Finds a campus by its ID.
     *
     * @param  campusId   the ID of the campus to find
     * @return            the campus found by the ID
     */
    public Campus findCampusById(Long campusId) {
        Optional<Campus> campus = campusRepository.findById(campusId);
        if(campus.isEmpty()) {
            throw new CampusExceptions("Campus is not found" );
        }
        return campus.get();
    }
}
