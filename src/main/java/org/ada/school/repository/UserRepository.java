package org.ada.school.repository;

import org.ada.school.model.User;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * @author Iván Camilo Rincón Saavedra
 * @version 1.0 2/3/2022
 * @project user-api
 */
@Repository
public interface UserRepository extends MongoRepository<User, String> {
    Optional<User> findById(String id);

    Optional<User> findByEmail(String email);

    List<User> findByCreatedAtAfter(String startDate);

    List<User> findByNameLikeOrLastNameLike(String pattern, String pattern2);
}