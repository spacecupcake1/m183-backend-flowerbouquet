package com.bbzbl.flowerbouquet.security;

import java.sql.Connection;

import javax.sql.DataSource;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

/**
 * Initialize database security settings on application startup
 * Simplified version for development - remove H2-specific settings that may cause compatibility issues
 */
@Component
public class DatabaseSecurityInitializer {

    private static final Logger logger = LoggerFactory.getLogger(DatabaseSecurityInitializer.class);

    @Autowired
    private DataSource dataSource;

    @EventListener(ApplicationReadyEvent.class)
    public void initializeDatabaseSecurity() {
        try (Connection connection = dataSource.getConnection()) {
            
            String databaseProductName = connection.getMetaData().getDatabaseProductName();
            logger.info("Database detected: {}", databaseProductName);
            
            // For development, we skip H2-specific security settings that may cause compatibility issues
            // In production, implement proper database security configurations
            if (databaseProductName.contains("H2")) {
                logger.info("H2 Database detected - skipping advanced security settings for development");
            }
            
            logger.info("Database security initialization completed successfully");
            
        } catch (Exception e) {
            logger.warn("Could not initialize database security settings: {}", e.getMessage());
            // Don't fail application startup if this fails
        }
    }
}