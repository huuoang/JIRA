package com.fas.models.dtos.requests;


import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class EmailRequestDTO {
    private String recipient;
    private String msgBody;
    private String subject;
    private String attachment;
}
