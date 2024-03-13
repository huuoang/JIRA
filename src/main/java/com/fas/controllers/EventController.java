package com.fas.controllers;

import com.fas.models.dtos.requests.EventRequestDTO;
import com.fas.models.dtos.requests.MajorRequestDTO;
import com.fas.models.dtos.responses.EventResponseDTO;
import com.fas.models.dtos.responses.MajorResponseDTO;
import com.fas.models.entities.Event;
import com.fas.models.entities.Major;
import com.fas.models.enums.Code;
import com.fas.models.utils.MessageDetails;
import com.fas.services.EventService;
import com.fas.services.MajorService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;


@RestController
public class EventController {

    @Autowired
    private EventService eventService;

    @PostMapping("/event")
    private MessageDetails<EventResponseDTO> createEvent(@RequestBody @Valid EventRequestDTO eventReq) {
        EventResponseDTO event = eventService.createEvent(eventReq);
        return new MessageDetails<EventResponseDTO>("Event created successfully", event, Code.SUCCESS);
    }

    @GetMapping("/event/{eventId}")
    private MessageDetails<EventResponseDTO> getEventById(@PathVariable UUID eventId) {
        Event event = eventService.getEventById(eventId);
        if(event == null) {
            return new MessageDetails<>("Get event failed", null, Code.FAILURE);
        }
        return new MessageDetails<>("Get event successfully", new EventResponseDTO(event), Code.SUCCESS);
    }


    @GetMapping("/event")
    private MessageDetails<List<EventResponseDTO>> getAllEvent() {
        List<EventResponseDTO> events = eventService.getAllEvents();
        return new MessageDetails<List<EventResponseDTO>>("Get all events successfully", events, Code.SUCCESS);
    }


    @PutMapping("/event/update/{eventId}")
    private MessageDetails<EventResponseDTO> updateEvent(@RequestBody EventRequestDTO event,@PathVariable  UUID eventId) {
        EventResponseDTO eventResponseDTO = eventService.updateEvent(event, eventId);
        return new MessageDetails<EventResponseDTO>("Update event successfully", eventResponseDTO, Code.SUCCESS);
    }


    @PutMapping("/event/delete/{eventId}")
    private MessageDetails<EventResponseDTO> deleteEvent(@PathVariable UUID eventId) {
        EventResponseDTO event =  eventService.deleteEvent(eventId);
        if(event == null) {
            return new MessageDetails<EventResponseDTO>("Delete event failed", null, Code.FAILURE);
        }
        return new MessageDetails<EventResponseDTO>("Delete event successfully", event, Code.SUCCESS);
    }
}
