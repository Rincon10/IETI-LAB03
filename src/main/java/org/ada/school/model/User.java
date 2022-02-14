package org.ada.school.model;

import org.ada.school.dto.UserDto;
import org.ada.school.model.enumData.RoleEnum;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.security.crypto.bcrypt.BCrypt;

import java.util.List;
import java.util.UUID;

@Document(collection = "User")
public class User {
    @Id
    private String id;
    private String name;
    @Indexed(unique = true)
    private String email;
    private String lastName;
    private String createdAt;
    private String passwordHash;
    private List<RoleEnum> roles;

    public User(UserDto dto) {
        this(dto.getName(), dto.getEmail(), dto.getLastName());
    }

    public User() {
        this.id = UUID.randomUUID().toString();
        this.createdAt = java.time.LocalDate.now().toString();
    }

    public User(String name, String email, String lastName) {
        this();
        this.name = name;
        this.email = email;
        this.lastName = lastName;

    }

    public User(String id, String name, String email, String lastName, String createdAt) {
        this(name, email, lastName);
        this.id = id;
        this.createdAt = createdAt;
    }

    public void update(UserDto userDto) {
        name = userDto.getName();
        lastName = userDto.getLastName();
        email = userDto.getEmail();
        if (userDto.getPassword() != null) {
            this.passwordHash = BCrypt.hashpw(userDto.getPassword(), BCrypt.gensalt());
        }
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    public String getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(String createdAt) {
        this.createdAt = createdAt;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public void setPasswordHash(String passwordHash) {
        this.passwordHash = passwordHash;
    }

    public List<RoleEnum> getRoles() {
        return roles;
    }

    public void setRoles(List<RoleEnum> roles) {
        this.roles = roles;
    }
}
