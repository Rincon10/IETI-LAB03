package org.ada.school.service.impl;

import org.ada.school.dto.UserDto;
import org.ada.school.model.User;
import org.ada.school.repository.UserRepository;
import org.ada.school.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * @author Iván Camilo Rincón Saavedra
 * @version 1.0 2/3/2022
 * @project user-api
 */

@Service
public class UserServiceMongoDB implements UserService {
    private final UserRepository userRepository;

    public UserServiceMongoDB(@Autowired UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public User create(User user) {
        userRepository.save(user);
        return user;
    }

    @Override
    public User findById(String id) {
        return userRepository.findById(id).get();
    }

    @Override
    public User findByEmail(String email) {
        return userRepository.findByEmail(email).get();
    }

    @Override
    public List<User> all() {
        return userRepository.findAll();
    }

    @Override
    public boolean deleteById(String id) {
        boolean deleted = true;
        try {
            if (findById(id) == null) throw new Exception();
            userRepository.deleteById(id);
        } catch (Exception exception) {
            deleted = false;
        }
        return deleted;
    }

    @Override
    public User update(UserDto userDto, String id) {
        User user = findById(id);
        user.update(userDto);
        return userRepository.save(user);
    }

    @Override
    public List<User> findUsersWithNameOrLastNameLike(String queryText) {
        return userRepository.findByNameLikeOrLastNameLike(queryText, queryText);
    }

    @Override
    public List<User> findUsersCreatedAfter(String startDate) {
        return userRepository.findByCreatedAtAfter(startDate);
    }
}
