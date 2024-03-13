package com.fas.services;

import com.fas.models.dtos.requests.AccountRequestDTO;
import com.fas.models.dtos.responses.AccountResponseDTO;
import com.fas.models.entities.Account;
import com.fas.models.exceptions.AccountExceptions;

import java.util.UUID;

public interface AccountService {


    public Account findAccountByEmail(String email);

    public AccountResponseDTO createAccount(AccountRequestDTO accountRequestDTO) throws AccountExceptions;

    public AccountResponseDTO changePassword(String password, UUID id) throws AccountExceptions;
}
