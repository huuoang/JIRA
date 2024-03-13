package com.fas.models.dtos.responses;

import com.fas.models.entities.Event;
import com.fas.models.entities.Major;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.UUID;

@Data
public class EventResponseDTO {
    private UUID id;

    private String image;

    private String url;

    private boolean status = true;

    private LocalDateTime createAt = LocalDateTime.now();

    private LocalDateTime updateAt = LocalDateTime.now();

    public EventResponseDTO(Event event) {
        this.id = event.getId();
        this.image = event.getImage();
        this.url = event.getUrl();
        this.status = event.isStatus();
        this.createAt = event.getCreateAt();
        this.updateAt = event.getUpdateAt();
    }
}
