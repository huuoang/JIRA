package com.fas.services;

import com.fas.models.dtos.requests.MajorRequestDTO;
import com.fas.models.dtos.responses.MajorResponseDTO;
import com.fas.models.entities.Major;

import java.util.List;
import java.util.UUID;

public interface MajorService {

    public MajorResponseDTO createMajor(MajorRequestDTO major);

    public MajorResponseDTO updateMajor(MajorRequestDTO major, UUID majorId);

    public MajorResponseDTO deleteMajor(UUID majorId);

    public Major getMajorById(UUID id);

    public List<MajorResponseDTO> getAllMajors();
}
