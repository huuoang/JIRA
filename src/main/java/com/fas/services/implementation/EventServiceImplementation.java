package com.fas.services.implementation;

import com.fas.models.dtos.requests.EventRequestDTO;
import com.fas.models.dtos.responses.EventResponseDTO;
import com.fas.models.entities.Event;
import com.fas.models.exceptions.EventExceptions;
import com.fas.repositories.EventRepository;
import com.fas.services.EventService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
public class EventServiceImplementation implements EventService {


    @Autowired
    private EventRepository eventRepository;

    @Override
    public EventResponseDTO createEvent(EventRequestDTO eventReq) {
        Event newEvent = eventReq.getEvent();
        Event savedEvent = eventRepository.save(newEvent);
        return new EventResponseDTO(savedEvent);    }

    @Override
    public EventResponseDTO updateEvent(EventRequestDTO event, UUID eventId) {
        Event existedEvent = getEventById(eventId);
        Event newEvent = event.getEvent();
        existedEvent.setImage(newEvent.getImage());
        existedEvent.setUrl(newEvent.getUrl());
        existedEvent.setUpdateAt(LocalDateTime.now());

        Event savedEvent = eventRepository.save(existedEvent);
        return new EventResponseDTO(savedEvent);
    }

    @Override
    public EventResponseDTO deleteEvent(UUID eventId) {
        Event existedEvent = getEventById(eventId);
        existedEvent.setUpdateAt(LocalDateTime.now());
        existedEvent.setStatus(!existedEvent.isStatus());
        Event savedEvent = eventRepository.save(existedEvent);
        return new EventResponseDTO(savedEvent);
    }

    @Override
    public Event getEventById(UUID id) {
        Optional<Event> event = eventRepository.findById(id);
        if(event.isEmpty()) {
            throw new EventExceptions("Event not found");
        }
        return event.get();
    }

    @Override
    public List<EventResponseDTO> getAllEvents() {
        List<Event> events = eventRepository.findAll();
        List<EventResponseDTO> listEvents = new ArrayList<>();
        for(Event event:events) {
            EventResponseDTO eventResponseDTO = new EventResponseDTO(event);
            listEvents.add(eventResponseDTO);
        }
        return listEvents;
    }

}
