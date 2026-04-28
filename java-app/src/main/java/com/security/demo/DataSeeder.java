// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Analyzer for C, C++, C#, and Java: https://pvs-studio.com

package com.security.demo;

import com.security.demo.model.Document;
import com.security.demo.model.User;
import com.security.demo.repository.DocumentRepository;
import com.security.demo.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.List;

/**
 * Data seeder to populate the database with test users and documents.
 * Runs automatically on application startup.
 */
@Component
@ConditionalOnProperty(value = "app.seed.enabled", havingValue = "true", matchIfMissing = true)
public class DataSeeder implements CommandLineRunner {
    
    private static final Logger logger = LoggerFactory.getLogger(DataSeeder.class);
    
    private final UserRepository userRepository;
    private final DocumentRepository documentRepository;
    
    public DataSeeder(UserRepository userRepository, DocumentRepository documentRepository) {
        this.userRepository = userRepository;
        this.documentRepository = documentRepository;
    }
    
    @Override
    public void run(String... args) {
        logger.info("Starting database seeding...");
        
        // Check if data already exists
        if (userRepository.count() > 0) {
            logger.info("Database already contains data, skipping seed");
            return;
        }
        
        try {
            // Create test users
            logger.info("Creating test users...");
            
            User alice = new User("alice", "user");
            User bob = new User("bob", "user");
            User charlie = new User("charlie", "user");
            User admin = new User("admin", "admin");
            User victim = new User("victim", "user");
            
            List<User> users = Arrays.asList(alice, bob, charlie, admin, victim);
            userRepository.saveAll(users);
            userRepository.flush();
            
            logger.info("Created {} users", users.size());
            
            // Create documents for users
            logger.info("Creating documents...");
            
            Document aliceDoc1 = new Document("alice_passport.pdf", alice);
            Document aliceDoc2 = new Document("alice_contract.pdf", alice);
            
            Document bobDoc1 = new Document("bob_id_card.pdf", bob);
            Document bobDoc2 = new Document("bob_bank_statement.pdf", bob);
            Document bobDoc3 = new Document("bob_medical_record.pdf", bob);
            
            Document charlieDoc1 = new Document("charlie_diploma.pdf", charlie);
            
            Document victimDoc1 = new Document("victim_secret_document.pdf", victim);
            Document victimDoc2 = new Document("victim_private_info.pdf", victim);
            
            List<Document> documents = Arrays.asList(
                aliceDoc1, aliceDoc2, bobDoc1, bobDoc2, bobDoc3, 
                charlieDoc1, victimDoc1, victimDoc2
            );
            
            documentRepository.saveAll(documents);
            
            logger.info("Created {} documents", documents.size());
            logger.info("✓ Database seeded successfully!");
            logger.info("Test users created:");
            
            for (User user : users) {
                long docCount = user.getDocs().size();
                logger.info("  - {} (id={}, role={}) - {} documents", 
                    user.getUsername(), user.getId(), user.getRole(), docCount);
            }
            
        } catch (Exception e) {
            logger.error("✗ Error seeding database", e);
        }
    }
}
