package org.ada.school.dto;

public class UserDto {
    private String name;
    private String email;
    private String lastName;
    private String password;

    public UserDto() {
    }

    public String getName() {
        return name;
    }

    public String getEmail() {
        return email;
    }

    public String getLastName() {
        return lastName;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
