package com.example.pets4ever.user;

import com.example.pets4ever.post.Post;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.List;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, String> {
    Optional<User> findByUsername(String username);
    Optional<User> findByEmail(String email);
    @Query(value = "SELECT u FROM Users u WHERE u.email = :email")
    UserDetails findByEmailToReturnUserDetails(String email);
    boolean existsByUsername(String username);
    boolean existsByEmail(String email);
    boolean existsByFullname(String fullname);
}
