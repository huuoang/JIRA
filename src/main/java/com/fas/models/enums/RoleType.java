package com.fas.models.enums;

public enum RoleType {
    ROLE_STUDENT("STUDENT"),
    ROLE_INSTRUCTOR("INSTRUCTOR"),
    ROLE_MANAGER("MANAGER"),
    ROLE_ADMIN("ADMIN");

    private final String name;

    RoleType(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }
}