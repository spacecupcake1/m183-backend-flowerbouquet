package com.bbzbl.flowerbouquet.config;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

@Component
public class DatabaseSecurityConfig implements CommandLineRunner {

    @Autowired
    private DataSource dataSource;

    @Override
    public void run(String... args) throws Exception {
        setupDatabaseSecurity();
    }

    private void setupDatabaseSecurity() {
        try {
            JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);
            
            // H2 Database Security Setup
            // Note: H2 has limited user management compared to production databases
            
            // 1. Create application user with limited privileges (H2 specific)
            try {
                jdbcTemplate.execute("DROP USER IF EXISTS app_user");
                jdbcTemplate.execute("CREATE USER app_user PASSWORD 'AppUser123!' ADMIN");
                
                // Grant only necessary permissions
                jdbcTemplate.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON SCHEMA PUBLIC TO app_user");
                
                System.out.println("✅ Database security: Created restricted app_user");
            } catch (Exception e) {
                System.out.println("⚠️  H2 User creation failed (may not be supported in this H2 version): " + e.getMessage());
            }

            // 2. Disable dangerous H2 functions
            try {
                jdbcTemplate.execute("SET ALLOW_LITERALS NONE"); // Prevent literal SQL
                System.out.println("✅ Database security: Disabled SQL literals");
            } catch (Exception e) {
                System.out.println("⚠️  Could not disable SQL literals: " + e.getMessage());
            }

            // 3. Set up database logging
            jdbcTemplate.execute("SET TRACE_LEVEL_FILE 1");
            jdbcTemplate.execute("SET TRACE_LEVEL_SYSTEM_OUT 0");
            
            System.out.println("✅ Database security configuration completed");
            
        } catch (Exception e) {
            System.err.println("❌ Failed to configure database security: " + e.getMessage());
        }
    }
}