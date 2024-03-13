package com.fas.services;

import com.fas.models.dtos.requests.EventRequestDTO;
import com.fas.models.dtos.responses.EventResponseDTO;
import com.fas.models.entities.Event;


import java.util.List;
import java.util.UUID;

public interface EventService {

    public EventResponseDTO createEvent(EventRequestDTO event);

    public EventResponseDTO updateEvent(EventRequestDTO event, UUID eventId);

    public EventResponseDTO deleteEvent(UUID eventId);

    public Event getEventById(UUID id);

    public List<EventResponseDTO> getAllEvents();
}
