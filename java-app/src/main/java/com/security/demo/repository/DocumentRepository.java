package com.security.demo.repository;

import com.security.demo.model.Document;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * Repository interface for Document entity operations.
 */
@Repository
public interface DocumentRepository extends JpaRepository<Document, Long> {
}
