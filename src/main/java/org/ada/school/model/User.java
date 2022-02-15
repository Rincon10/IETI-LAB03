package org.ada.school.model;

import org.ada.school.dto.UserDto;
import org.ada.school.model.enumData.RoleEnum;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.security.crypto.bcrypt.BCrypt;

import java.util.ArrayList;
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
    private String password;
    private List<RoleEnum> roles = new ArrayList<>();

    public User(UserDto dto) {
        this(dto.getName(), dto.getEmail(), dto.getLastName(), dto.getPassword());
    }

    public User() {
        this.id = UUID.randomUUID().toString();
        this.createdAt = java.time.LocalDate.now().toString();
        this.roles = new ArrayList<>();
    }

    public User(String name, String email, String lastName, String password) {
        this();
        this.name = name;
        this.email = email;
        this.lastName = lastName;
        hashPassword(password);


    }

    public User(String id, String name, String email, String lastName,String password, String createdAt) {
        this(name, email, lastName, password);
        this.id = id;
        this.createdAt = createdAt;
    }

    public void update(UserDto userDto) {
        name = userDto.getName();
        lastName = userDto.getLastName();
        email = userDto.getEmail();
        hashPassword(userDto.getPassword());
    }

    private void hashPassword(String password){
        if (password != null) {
            this.password = BCrypt.hashpw(password, BCrypt.gensalt());
        }
    }

    public void addRole( RoleEnum roleEnum ){
        if( !roles.contains( roleEnum)) roles.add(roleEnum);
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

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        hashPassword(password);
    }

    public List<RoleEnum> getRoles() {
        return roles;
    }

    public void setRoles(List<RoleEnum> roles) {
        this.roles = roles;
    }
}
