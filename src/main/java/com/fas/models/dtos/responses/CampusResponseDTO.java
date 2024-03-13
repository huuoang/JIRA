package com.fas.models.dtos.responses;

import com.fas.models.entities.Campus;
import com.fas.models.enums.CampusName;
import lombok.Data;

@Data
public class CampusResponseDTO {
    private Long id;
    private CampusName name;
    private String location;

    public CampusResponseDTO(Campus campus) {
        this.id = campus.getId();
        this.name = campus.getName();
        this.location = campus.getLocation();
    }
}
