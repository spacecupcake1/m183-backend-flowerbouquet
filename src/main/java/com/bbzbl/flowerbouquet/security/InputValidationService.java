package com.bbzbl.flowerbouquet.security;

import java.util.regex.Pattern;

import org.springframework.stereotype.Service;

/**
 * Service for validating and sanitizing user inputs to prevent security vulnerabilities.
 * Provides protection against XSS attacks, SQL injection, and other malicious inputs.
 */
@Service
public class InputValidationService {

    // Patterns for detecting potentially malicious content

    private static final Pattern HTML_TAG_PATTERN = Pattern.compile(
        "<[^>]+>",
        Pattern.CASE_INSENSITIVE
    );

    // Dangerous characters that could be used for injection attacks
    private static final Pattern DANGEROUS_CHARS_PATTERN = Pattern.compile(
        "[<>\"'%;()&+]"
    );

    // Valid patterns for different types of input
    private static final Pattern VALID_USERNAME_PATTERN = Pattern.compile(
        "^[a-zA-Z0-9_-]{3,50}$"
    );

    private static final Pattern VALID_NAME_PATTERN = Pattern.compile(
        "^[a-zA-ZÀ-ÿ\\s'-]{2,50}$"
    );

    private static final Pattern VALID_EMAIL_PATTERN = Pattern.compile(
        "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$"
    );
    
    private static final Pattern SQL_INJECTION_PATTERN = Pattern.compile(
        ".*('|(\\-\\-)|(;)|(\\|)|(\\*)|(%)|(\\bOR\\b)|(\\bAND\\b)|(\\bUNION\\b)|(\\bSELECT\\b)|(\\bINSERT\\b)|(\\bDELETE\\b)|(\\bUPDATE\\b)|(\\bDROP\\b)|(\\bCREATE\\b)|(\\bALTER\\b)).*",
        Pattern.CASE_INSENSITIVE
    );
    
    public void validateSearchInput(String searchTerm) {
        if (searchTerm != null && searchTerm.length() > 100) {
            throw new IllegalArgumentException("Search term too long");
        }
        
        if (searchTerm != null && SQL_INJECTION_PATTERN.matcher(searchTerm).matches()) {
            throw new IllegalArgumentException("Invalid search term");
        }
    }

    /**
     * Validates and sanitizes input string for security threats.
     * 
     * @param input the input string to validate
     * @return ValidationResult containing validation status and sanitized input
     */
    public ValidationResult validateAndSanitize(String input) {
        if (input == null) {
            return new ValidationResult(false, "", "Input cannot be null");
        }

        if (input.trim().isEmpty()) {
            return new ValidationResult(false, "", "Input cannot be empty");
        }

        // Check for SQL injection patterns
        if (SQL_INJECTION_PATTERN.matcher(input).matches()) {
            return new ValidationResult(false, "", "Potential SQL injection detected");
        }

        // Check for XSS patterns
        if (XSS_PATTERN.matcher(input).matches()) {
            return new ValidationResult(false, "", "Potential XSS attack detected");
        }

        // Sanitize the input
        String sanitized = sanitizeInput(input);

        // Additional validation after sanitization
        if (sanitized.length() != input.length()) {
            // Input was modified during sanitization, might contain malicious content
            return new ValidationResult(false, sanitized, "Input contains potentially dangerous content");
        }

        return new ValidationResult(true, sanitized, null);
    }

    /**
     * Validates username format and security.
     * 
     * @param username the username to validate
     * @return true if valid, false otherwise
     */
    public boolean isValidUsername(String username) {
        if (username == null) return false;
        
        // Check format
        if (!VALID_USERNAME_PATTERN.matcher(username).matches()) {
            return false;
        }

        // Check for security threats
        ValidationResult result = validateAndSanitize(username);
        return result.isValid();
    }

    /**
     * Validates name format and security.
     * 
     * @param name the name to validate
     * @return true if valid, false otherwise
     */
    public boolean isValidName(String name) {
        if (name == null) return false;
        
        // Check format
        if (!VALID_NAME_PATTERN.matcher(name).matches()) {
            return false;
        }

        // Check for security threats
        ValidationResult result = validateAndSanitize(name);
        return result.isValid();
    }

    /**
     * Validates email format and security.
     * 
     * @param email the email to validate
     * @return true if valid, false otherwise
     */
    public boolean isValidEmail(String email) {
        if (email == null) return false;
        
        // Check format
        if (!VALID_EMAIL_PATTERN.matcher(email).matches()) {
            return false;
        }

        // Check for security threats
        ValidationResult result = validateAndSanitize(email);
        return result.isValid();
    }

    /**
     * Validates password security without sanitizing (to preserve special characters).
     * 
     * @param password the password to validate
     * @return true if secure, false otherwise
     */
    public boolean isSecurePassword(String password) {
        if (password == null || password.length() < 8) {
            return false;
        }

        // Check for obvious injection attempts without sanitizing
        if (SQL_INJECTION_PATTERN.matcher(password).matches() || 
            XSS_PATTERN.matcher(password).matches()) {
            return false;
        }

        return true;
    }

    /**
     * Removes null characters and other control characters that might be used in attacks.
     * 
     * @param input the input to clean
     * @return cleaned input
     */
    public String removeControlCharacters(String input) {
        if (input == null) return "";
        
        // Remove null bytes and other control characters
        return input.replaceAll("[\u0000-\u001f\u007f-\u009f]", "");
    }

    /**
     * Validates that input doesn't contain dangerous file path characters.
     * 
     * @param input the input to validate
     * @return true if safe, false otherwise
     */
    public boolean isSafeFilePath(String input) {
        if (input == null) return false;
        
        // Check for path traversal attempts
        return !input.contains("..") && 
               !input.contains("/") && 
               !input.contains("\\") && 
               !input.contains(":") &&
               !input.contains("|") &&
               !input.contains("*") &&
               !input.contains("?");
    }

    /**
     * Inner class to hold validation results.
     */
    public static class ValidationResult {
        private final boolean valid;
        private final String sanitized;
        private final String error;

        public ValidationResult(boolean valid, String sanitized, String error) {
            this.valid = valid;
            this.sanitized = sanitized;
            this.error = error;
        }

        public boolean isValid() { return valid; }
        public String getSanitized() { return sanitized; }
        public String getError() { return error; }
    }

    private static final Pattern XSS_PATTERN = Pattern.compile(
        ".*(<script|javascript:|on\\w+\\s*=|<iframe|<object|<embed|<form|<input|<meta|<link).*",
        Pattern.CASE_INSENSITIVE | Pattern.DOTALL
    );
    
    private static final Pattern HTML_PATTERN = Pattern.compile("<[^>]*>");

    /**
     * Comprehensive input sanitization
     */
    public String sanitizeInput(String input) {
        if (input == null) return null;
        
        // Remove HTML tags
        String sanitized = HTML_PATTERN.matcher(input).replaceAll("");
        
        // Remove potential XSS patterns
        sanitized = sanitized.replaceAll("(?i)javascript:", "");
        sanitized = sanitized.replaceAll("(?i)on\\w+\\s*=", "");
        sanitized = sanitized.replaceAll("(?i)expression\\s*\\(", "");
        
        // HTML entity encoding
        sanitized = htmlEncode(sanitized);
        
        return sanitized.trim();
    }
    
    /**
     * Validate input for XSS patterns
     */
    public void validateInput(String input, String fieldName) {
        if (input != null && XSS_PATTERN.matcher(input).matches()) {
            throw new IllegalArgumentException("Invalid input in field: " + fieldName);
        }
    }
    
    /**
     * HTML encode special characters
     */
    private String htmlEncode(String input) {
        return input
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;")
            .replace("'", "&#x27;")
            .replace("/", "&#x2F;");
    }
}