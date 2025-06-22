package com.bbzbl.flowerbouquet.validation;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import org.springframework.stereotype.Service;
import org.springframework.web.util.HtmlUtils;

/**
 * Basic security validation service for input validation and sanitization.
 * Provides protection against XSS attacks, SQL injection, and other malicious inputs.
 */
@Service
public class SecurityValidationService {

    // Security patterns for threat detection
    private static final Pattern SQL_INJECTION_PATTERN = Pattern.compile(
        ".*('|(\\-\\-)|(;)|(\\|)|(\\*)|(%)|(\\bOR\\b)|(\\bAND\\b)|(\\bUNION\\b)|(\\bSELECT\\b)|" +
        "(\\bINSERT\\b)|(\\bDELETE\\b)|(\\bUPDATE\\b)|(\\bDROP\\b)|(\\bCREATE\\b)|(\\bALTER\\b)|" +
        "(\\bEXEC\\b)|(\\bEXECUTE\\b)).*",
        Pattern.CASE_INSENSITIVE
    );

    private static final Pattern XSS_PATTERN = Pattern.compile(
        ".*(<script[^>]*>|</script>|javascript:|vbscript:|on\\w+\\s*=|expression\\s*\\(|url\\s*\\(|" +
        "behavior\\s*:|<iframe[^>]*>|<object[^>]*>|<embed[^>]*>|<applet[^>]*>|<meta[^>]*>|" +
        "<form[^>]*>|<input[^>]*>).*",
        Pattern.CASE_INSENSITIVE
    );

    private static final Pattern PATH_TRAVERSAL_PATTERN = Pattern.compile(
        ".*(\\.\\.[\\\\/]|[\\\\/]\\.\\.[\\\\/]|\\.\\.[\\\\/]|[\\\\/]\\.\\.|\\%2e\\%2e|\\%252e\\%252e).*"
    );

    // Valid patterns for different input types
    private static final Pattern VALID_USERNAME_PATTERN = Pattern.compile("^[a-zA-Z0-9_-]{3,50}$");
    private static final Pattern VALID_NAME_PATTERN = Pattern.compile("^[a-zA-ZÀ-ÿ\\s'-]{2,50}$");
    private static final Pattern VALID_EMAIL_PATTERN = Pattern.compile("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$");
    private static final Pattern VALID_FLOWER_NAME_PATTERN = Pattern.compile("^[a-zA-Z0-9\\s\\-'.,]{2,100}$");
    private static final Pattern VALID_URL_PATTERN = Pattern.compile("^https?://[\\w.-]+(:\\d+)?(/.*)?$");

    /**
     * Input types for validation
     */
    public enum InputType {
        USERNAME, EMAIL, NAME, FLOWER_NAME, PRICE, DESCRIPTION, 
        SEARCH_TERM, HTML_CONTENT, URL, FILE_PATH, GENERIC
    }

    /**
     * Comprehensive input validation for all user inputs
     */
    public ValidationResult validateInput(String input, String fieldName, InputType type) {
        List<String> violations = new ArrayList<>();
        
        if (input == null) {
            return new ValidationResult(true, null, null);
        }

        // 1. Check for SQL Injection
        if (SQL_INJECTION_PATTERN.matcher(input).matches()) {
            violations.add("Potential SQL injection detected");
        }

        // 2. Check for XSS
        if (XSS_PATTERN.matcher(input).matches()) {
            violations.add("Potential XSS attack detected");
        }

        // 3. Check for Path Traversal
        if (PATH_TRAVERSAL_PATTERN.matcher(input).matches()) {
            violations.add("Path traversal attempt detected");
        }

        // 4. Type-specific validation
        List<String> typeValidationErrors = validateByType(input, type);
        violations.addAll(typeValidationErrors);

        // 5. Length validation
        if (input.length() > getMaxLengthForType(type)) {
            violations.add("Input exceeds maximum allowed length");
        }

        // Sanitize input
        String sanitized = sanitizeInput(input, type);

        boolean isValid = violations.isEmpty();
        return new ValidationResult(isValid, sanitized, violations);
    }

    /**
     * Type-specific validation
     */
    private List<String> validateByType(String input, InputType type) {
        List<String> errors = new ArrayList<>();

        switch (type) {
            case USERNAME:
                if (!VALID_USERNAME_PATTERN.matcher(input).matches()) {
                    errors.add("Username must be 3-50 characters, alphanumeric, underscore, or dash only");
                }
                break;
            case EMAIL:
                if (!VALID_EMAIL_PATTERN.matcher(input).matches()) {
                    errors.add("Invalid email format");
                }
                break;
            case NAME:
                if (!VALID_NAME_PATTERN.matcher(input).matches()) {
                    errors.add("Name must be 2-50 characters, letters, spaces, apostrophes, or hyphens only");
                }
                break;
            case FLOWER_NAME:
                if (!VALID_FLOWER_NAME_PATTERN.matcher(input).matches()) {
                    errors.add("Flower name contains invalid characters");
                }
                break;
            case PRICE:
                if (!input.matches("^\\d+(\\.\\d{1,2})?$")) {
                    errors.add("Price must be a valid number with up to 2 decimal places");
                }
                break;
            case SEARCH_TERM:
                if (input.length() > 100) {
                    errors.add("Search term too long");
                }
                break;
            case URL:
                if (!VALID_URL_PATTERN.matcher(input).matches()) {
                    errors.add("Invalid URL format");
                }
                break;
        }

        return errors;
    }

    /**
     * Input sanitization based on type
     */
    private String sanitizeInput(String input, InputType type) {
        if (input == null) return null;

        String sanitized = input.trim();

        switch (type) {
            case HTML_CONTENT:
                // For HTML content, use comprehensive escaping
                sanitized = HtmlUtils.htmlEscape(sanitized);
                break;
            case SEARCH_TERM:
                // Remove dangerous characters but allow basic search
                sanitized = sanitized.replaceAll("[<>\"'%;()&+]", "");
                break;
            case URL:
                // Basic URL sanitization
                sanitized = sanitized.replaceAll("[<>\"'\\s]", "");
                break;
            default:
                // Default sanitization for most fields
                sanitized = HtmlUtils.htmlEscape(sanitized);
                break;
        }

        return sanitized;
    }

    /**
     * Get maximum length for input type
     */
    private int getMaxLengthForType(InputType type) {
        switch (type) {
            case USERNAME: return 50;
            case EMAIL: return 100;
            case NAME: return 50;
            case FLOWER_NAME: return 100;
            case DESCRIPTION: return 1000;
            case SEARCH_TERM: return 100;
            case URL: return 255;
            case FILE_PATH: return 255;
            default: return 255;
        }
    }

    /**
     * Validation result class
     */
    public static class ValidationResult {
        private final boolean valid;
        private final String sanitized;
        private final List<String> errors;

        public ValidationResult(boolean valid, String sanitized, List<String> errors) {
            this.valid = valid;
            this.sanitized = sanitized;
            this.errors = errors != null ? errors : new ArrayList<>();
        }

        public boolean isValid() { return valid; }
        public String getSanitized() { return sanitized; }
        public List<String> getErrors() { return errors; }
        public String getFirstError() { 
            return errors.isEmpty() ? null : errors.get(0); 
        }
    }
}