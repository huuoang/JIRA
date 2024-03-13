package com.fas.controllers;

import com.fas.models.dtos.requests.AccountRequestDTO;
import com.fas.models.dtos.requests.EmailRequestDTO;
import com.fas.models.dtos.requests.LoginGoogleRequest;
import com.fas.models.dtos.responses.AccountResponseDTO;
import com.fas.models.entities.Account;
import com.fas.models.entities.Campus;
import com.fas.models.entities.Role;
import com.fas.models.enums.Code;
import com.fas.models.exceptions.AccountExceptions;
import com.fas.models.exceptions.RoleExceptions;
import com.fas.models.utils.MessageDetails;
import com.fas.securities.jwt.JwtProvider;
import com.fas.securities.services.AccountDetailsService;
import com.fas.services.AccountService;
import com.fas.services.CampusService;
import com.fas.services.EmailService;
import com.fas.services.RoleSevice;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;

@RestController
@RequestMapping("/account")
public class AccountController {

    private final AccountService accountService;
    private final RoleSevice roleSevice;
    private final CampusService campusService;
    private final JwtProvider jwtProvider;
    private final PasswordEncoder passwordEncoder;
    private final AccountDetailsService accountDetailsService;

    private final EmailService emailService;

    @Autowired
    public AccountController(AccountService accountService, RoleSevice roleSevice,
                             CampusService campusService, JwtProvider jwtProvider,
                             PasswordEncoder passwordEncoder,
                             AccountDetailsService accountDetailsService, EmailService emailService) {
        this.accountService = accountService;
        this.roleSevice = roleSevice;
        this.campusService = campusService;
        this.jwtProvider = jwtProvider;
        this.passwordEncoder = passwordEncoder;
        this.accountDetailsService = accountDetailsService;
        this.emailService = emailService;
    }
    private static final String email="manh@gmail.com";

    /**
     * loginUser method to authenticate and generate token for the user, and handle login logic.
     *
     * @param  accountRequestDTO	request object for user account
     * @return         	MessageDetails object containing login status and account details
     */
    @PostMapping("/signin")
    public MessageDetails<AccountResponseDTO> loginUser(@RequestBody @Valid AccountRequestDTO accountRequestDTO) throws AccountExceptions, RoleExceptions {
        Account account = accountRequestDTO.getAccount();

        Authentication authentication = authenticate(email, account.getPassword());
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String token = jwtProvider.generateToken(authentication);

        Campus existingCampus = campusService.findCampusById(account.getCampus().getId());

        Role existingRole = roleSevice.findRoleById(account.getRole().getId());

        Account existingAccount = accountService.findAccountByEmail(account.getEmail());
        if(existingAccount != null && existingCampus != null && existingRole != null
                && existingAccount.getRole().getType().equals(existingRole.getType())
                && existingAccount.getCampus().getName().equals(existingCampus.getName())) {
            AccountResponseDTO accountResponseDTO = new AccountResponseDTO(existingAccount);
            accountResponseDTO.setAccessToken(token);

            return new MessageDetails<>("Login successfully", accountResponseDTO, Code.SUCCESS);
        }

        return new MessageDetails<>("Login failed", null, Code.FAILURE);
    }

    /**
     * A method to login a user using Google authentication.
     *
     * @param  request   the LoginGoogleRequest containing the user's Google login information
     * @return          a MessageDetails object containing the login status and account details
     */
    @PostMapping("/signin/google")
    public MessageDetails<AccountResponseDTO> loginUserByGoogle(@RequestBody @Valid LoginGoogleRequest request) throws AccountExceptions, RoleExceptions {
        Account account = request.getAccount();

        Account existingAccount = accountService.findAccountByEmail(account.getEmail());

        Campus existingCampus = campusService.findCampusById(account.getCampus().getId());

        Authentication authentication = authenticate(account.getEmail());

        String token = jwtProvider.generateToken(authentication);

        if(existingAccount != null && existingCampus != null && existingAccount.getCampus().getName().equals(existingCampus.getName())) {
            AccountResponseDTO accountResponseDTO = new AccountResponseDTO(existingAccount);
            accountResponseDTO.setAccessToken(token);

            return new MessageDetails<>("Login successfully", accountResponseDTO, Code.SUCCESS);
        }

        return new MessageDetails<>("Login failed", null, Code.FAILURE);
    }

    private static final Random random = new Random();
    public synchronized  String generatePassword() {
        String words = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder randomStringBuilder = new StringBuilder();

        for (int i = 0; i < 8; i++) {
            int index = ThreadLocalRandom.current().nextInt(words.length());
            randomStringBuilder.append(words.charAt(index));
        }
        return randomStringBuilder.toString();
    }


    @GetMapping("/signin/forgotpassword")
    public MessageDetails<AccountResponseDTO> checkEmailExist(@RequestParam @Valid String email) throws AccountExceptions, RoleExceptions {
        Account account = accountService.findAccountByEmail(email);
        if(account == null) {
            return new MessageDetails<>("Email not exist", null, Code.FAILURE);
        }
        AccountResponseDTO accountResponseDTO = new AccountResponseDTO(account);

        EmailRequestDTO details = new EmailRequestDTO();
        String password = "123123";

        details.setRecipient(account.getEmail());
        details.setSubject("Reset Password");
        details.setMsgBody("Your new password is: " + password);

        accountService.changePassword(password, account.getId());

        return new MessageDetails<>("Change password successfully", accountResponseDTO, Code.SUCCESS);
    }


    /**
     * Authenticates the user with the given email and password.
     *
     * @param  email     the user's email
     * @param  password  the user's password
     * @return           the authenticated user details
     */
    private static final String BAD_CREDENTIALS_MESSAGE = "Your email, or password is incorrect. Please try again";
    private Authentication authenticate(String email, String password) {
        UserDetails userDetails = accountDetailsService.loadUserByUsername(email);

        if(userDetails == null) {
            throw new BadCredentialsException(BAD_CREDENTIALS_MESSAGE);
        }

        if(!passwordEncoder.matches(password, userDetails.getPassword())) {
            throw new BadCredentialsException(BAD_CREDENTIALS_MESSAGE);
        }

        return new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
    }

    private Authentication authenticate(String email) {
        UserDetails userDetails = accountDetailsService.loadUserByUsername(email);

        if(userDetails == null) {
            throw new BadCredentialsException(BAD_CREDENTIALS_MESSAGE);
        }

        return new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
    }

    @PostMapping("/signin/sendMail")
    public String sendMail(@RequestBody EmailRequestDTO details) {
        String status = emailService.sendSimpleMail(details);
        return status;
    }

    // Sending email with attachment
    @PostMapping("/sendMailWithAttachment")
    public String sendMailWithAttachment(
            @RequestBody EmailRequestDTO details)
    {
        String status
                = emailService.sendMailWithAttachment(details);

        return status;
    }
}
