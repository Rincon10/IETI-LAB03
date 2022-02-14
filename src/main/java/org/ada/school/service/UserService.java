package org.ada.school.service;

import org.ada.school.dto.UserDto;
import org.ada.school.model.User;

import java.util.List;

public interface UserService
{
    User create( User user );

    User findById( String id );

    User findByEmail( String email);

    List<User> all();

    boolean deleteById( String id );

    User update( UserDto userDto, String id );

    List<User> findUsersWithNameOrLastNameLike(String queryText);

    List<User> findUsersCreatedAfter(String startDate);
}
