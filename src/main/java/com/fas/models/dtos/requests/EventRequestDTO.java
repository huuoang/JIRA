package com.fas.models.dtos.requests;

import com.fas.models.entities.Event;
import com.fas.models.entities.Major;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.UUID;

@Data
public class EventRequestDTO {
    private UUID id;

    private String image;

    private String url;

    private boolean status = true;

    private LocalDateTime createAt = LocalDateTime.now();

    private LocalDateTime updateAt = LocalDateTime.now();

    public Event getEvent() {
        return new Event(id, image, url,status, createAt, updateAt);
    }
}
