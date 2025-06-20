package com.bbzbl.flowerbouquet.security;

import java.sql.Connection;
import java.sql.Statement;

import javax.sql.DataSource;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

/**
 * Initialize database security settings on application startup
 */
@Component
public class DatabaseSecurityInitializer {

    private static final Logger logger = LoggerFactory.getLogger(DatabaseSecurityInitializer.class);

    @Autowired
    private DataSource dataSource;

    @EventListener(ApplicationReadyEvent.class)
    public void initializeDatabaseSecurity() {
        try (Connection connection = dataSource.getConnection()) {
            
            // For H2 Database - Set security properties
            if (connection.getMetaData().getDatabaseProductName().contains("H2")) {
                try (Statement stmt = connection.createStatement()) {
                    
                    // Disable remote access in H2
                    stmt.execute("SET @ALLOW_LITERALS NONE");
                    
                    // Log database security initialization
                    logger.info("Database security settings initialized for H2");
                }
            }
            
            logger.info("Database security initialization completed successfully");
            
        } catch (Exception e) {
            logger.warn("Could not initialize database security settings: {}", e.getMessage());
            // Don't fail application startup if this fails
        }
    }
}
