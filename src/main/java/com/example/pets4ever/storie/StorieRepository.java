package com.example.pets4ever.storie;

import org.springframework.data.jpa.repository.JpaRepository;
import java.time.LocalDateTime;

public interface StorieRepository extends JpaRepository<Storie, String> {
    void deleteByExpirationTimeBeforeAndExpirationTimeIsNotNull(LocalDateTime expirationTime);
}
