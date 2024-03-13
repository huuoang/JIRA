package com.fas.services.implementation;

import com.fas.models.dtos.requests.AccountRequestDTO;
import com.fas.models.dtos.responses.AccountResponseDTO;
import com.fas.models.entities.Account;
import com.fas.models.exceptions.AccountExceptions;
import com.fas.repositories.AccountRepository;
import com.fas.services.AccountService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
public class AccountServiceImplementation implements AccountService {
    @Autowired
    private AccountRepository accountRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public Account findAccountByEmail(String email) {
        return accountRepository.findByEmail(email);
    }

    @Override
    public AccountResponseDTO createAccount(AccountRequestDTO accountRequestDTO) {

        Account account = accountRequestDTO.getAccount();
        account.setPassword(passwordEncoder.encode(accountRequestDTO.getPassword()));

        Account savedAccount = accountRepository.save(account);
        return new AccountResponseDTO(savedAccount);
    }

    @Override
    public AccountResponseDTO changePassword(String password, UUID id) throws AccountExceptions {
        Account oldAccount = accountRepository.findById(id).orElseThrow(() -> new AccountExceptions("Account not found"));
        oldAccount.setPassword(passwordEncoder.encode(password));
        Account savedAccount = accountRepository.save(oldAccount);
        return new AccountResponseDTO(savedAccount);
    }
}
