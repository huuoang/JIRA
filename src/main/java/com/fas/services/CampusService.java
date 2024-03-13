package com.fas.services;

import com.fas.models.dtos.responses.CampusResponseDTO;
import com.fas.models.entities.Campus;
import com.fas.models.enums.CampusName;

import java.util.List;

public interface CampusService {
    public Campus findByCampusName(CampusName name);

    public Campus findCampusById(Long campusId);

    public List<CampusResponseDTO> findAllCampuses();
}
