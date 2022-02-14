package org.ada.school.dto;

/**
 * @author Iván Camilo Rincón Saavedra
 * @version 1.0 2/13/2022
 * @project user-api
 */
public class LoginDto {
    private String email;
    private String password;

    public LoginDto(String email, String password) {
        this.email = email;
        this.password = password;
    }

    public String getEmail() {
        return email;
    }

    public String getPassword() {
        return password;
    }
}