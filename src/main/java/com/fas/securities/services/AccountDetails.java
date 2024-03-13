package com.fas.securities.services;

import com.fas.models.entities.Account;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class AccountDetails implements UserDetails{
    private String email;
    private String password;
    private List<GrantedAuthority> authorities;

    public AccountDetails(String email, String password, List<GrantedAuthority> authorities) {
        this.email = email;
        this.password = password;
        this.authorities = authorities;
    }

    public static UserDetails buildUserDetails(Account account) {

        GrantedAuthority authority = new SimpleGrantedAuthority(account.getRole().getType().name());

        List<GrantedAuthority> authorities = new ArrayList();

        authorities.add(authority);

        return new AccountDetails(account.getEmail(), account.getPassword(), authorities);
    }


    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

}
