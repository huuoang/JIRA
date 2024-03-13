package com.fas.models.dtos.requests;

import com.fas.models.entities.Account;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class LoginGoogleRequest {
    private String email;

    @NotNull(message = "Campus must not be null")
    private long campusId;

    public Account getAccount() {
        return new Account(email, campusId);
    }
}
