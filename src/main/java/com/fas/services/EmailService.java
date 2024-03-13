package com.fas.services;

import com.fas.models.dtos.requests.EmailRequestDTO;

public interface EmailService {

    // Method
    // To send a simple email
    String sendSimpleMail(EmailRequestDTO details);

    // Method
    // To send an email with attachment
    String sendMailWithAttachment(EmailRequestDTO details);
}
