package org.ada.school.controller;

import org.ada.school.dto.UserDto;
import org.ada.school.model.User;
import org.ada.school.model.enumData.RoleEnum;
import org.ada.school.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.modelmapper.ModelMapper;

import javax.annotation.security.RolesAllowed;
import java.util.List;

@RestController
@CrossOrigin(origins = "*")
@RequestMapping("/api/v1/user")
public class UserController {

    private final UserService userService;

    public UserController(@Autowired UserService userService) {
        this.userService = userService;
    }


    @GetMapping
    public ResponseEntity<List<User>> all() {
        return ResponseEntity.ok(userService.all());
    }

    @GetMapping("/{id}")
    public ResponseEntity<User> findById(@PathVariable String id) {
        return ResponseEntity.ok(userService.findById(id));
    }

    @GetMapping("/createdAfter/{date}")
    public ResponseEntity<List<User>> findUsersCreatedAfter(@PathVariable String date) {
        return ResponseEntity.ok(userService.findUsersCreatedAfter(date));
    }

    @GetMapping("/like/{pattern}")
    public ResponseEntity<List<User>> findUsersWithNameOrLastNameLike(@PathVariable String pattern) {
        return ResponseEntity.ok(userService.findUsersWithNameOrLastNameLike(pattern));
    }


    @PostMapping
    public ResponseEntity<User> create(@RequestBody UserDto userDto) {
        ModelMapper modelMapper = new ModelMapper();
        User user = modelMapper.map(userDto, User.class);
//        user.addRole(RoleEnum.ADMIN);
        return ResponseEntity.ok(userService.create(user));
    }

    @PutMapping("/{id}")
//    @RolesAllowed("ADMIN")
    public ResponseEntity<User> update(@RequestBody UserDto userDto, @PathVariable String id) {
        return ResponseEntity.ok(userService.update(userDto, id));
    }

    @DeleteMapping("/{id}")
    @RolesAllowed("ADMIN")
    public ResponseEntity<Boolean> delete(@PathVariable String id) {
        return ResponseEntity.ok(userService.deleteById(id));
    }

}
