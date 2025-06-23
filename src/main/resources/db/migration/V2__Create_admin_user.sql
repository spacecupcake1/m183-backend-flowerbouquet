-- Create default admin user (H2 compatible)
-- Password is: Admin123! (hashed with BCrypt)
MERGE INTO users (username, email, password, firstname, lastname, enabled, email_verified) 
VALUES (
    'admin',
    'admin@flowerbouquet.local',
    '$2a$12$LQv3c1yqBw6Ubz2lGnQPGeRF/aW5NcV8UZ.FzPGG5gGJWD7xkmb.W',
    'System',
    'Administrator',
    TRUE,
    TRUE
);

-- Assign admin role to admin user (H2 compatible)
MERGE INTO user_roles (user_id, role_id)
SELECT u.id, r.id
FROM users u, roles r
WHERE u.username = 'admin' AND r.name = 'ROLE_ADMIN';