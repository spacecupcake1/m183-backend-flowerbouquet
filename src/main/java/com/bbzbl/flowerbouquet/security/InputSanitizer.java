package com.bbzbl.flowerbouquet.security;

import java.util.regex.Pattern;

import org.springframework.stereotype.Component;
import org.springframework.web.util.HtmlUtils;

/**
 * Utility class for sanitizing and validating user input to prevent security vulnerabilities.
 */
@Component
public class InputSanitizer {

    // Patterns for detecting potential security threats
    private static final Pattern SQL_INJECTION_PATTERN = Pattern.compile(
            "'|--|;|\\||\\*|%|union|select|insert|delete|update|drop|exec", Pattern.CASE_INSENSITIVE);
    
    private static final Pattern XSS_PATTERN = Pattern.compile(
            "<[^>]+>|javascript:|vbscript:|onload|onerror|onclick", Pattern.CASE_INSENSITIVE);
    
    private static final Pattern SCRIPT_PATTERN = Pattern.compile(
            "<script[^>]*>.*?</script>", Pattern.CASE_INSENSITIVE | Pattern.DOTALL);

    /**
     * Sanitize input to prevent XSS attacks.
     * 
     * @param input The input string to sanitize
     * @return Sanitized string safe for output
     */
    public String sanitizeForOutput(String input) {
        if (input == null) {
            return null;
        }
        
        // HTML escape the input
        String sanitized = HtmlUtils.htmlEscape(input);
        
        // Remove any remaining script tags
        sanitized = SCRIPT_PATTERN.matcher(sanitized).replaceAll("");
        
        return sanitized.trim();
    }

    /**
     * Validate input to detect potential SQL injection attempts.
     * 
     * @param input The input string to validate
     * @throws SecurityException if potential SQL injection is detected
     */
    public void validateForSqlInjection(String input) {
        if (input == null) {
            return;
        }
        
        if (SQL_INJECTION_PATTERN.matcher(input).find()) {
            throw new SecurityException("Potential SQL injection attempt detected");
        }
    }

    /**
     * Validate input to detect potential XSS attempts.
     * 
     * @param input The input string to validate
     * @throws SecurityException if potential XSS is detected
     */
    public void validateForXss(String input) {
        if (input == null) {
            return;
        }
        
        if (XSS_PATTERN.matcher(input).find()) {
            throw new SecurityException("Potential XSS attempt detected");
        }
    }

    /**
     * Comprehensive input validation that checks for multiple security threats.
     * 
     * @param input The input string to validate
     * @throws SecurityException if any security threat is detected
     */
    public void validateInput(String input) {
        validateForSqlInjection(input);
        validateForXss(input);
        validateInputLength(input);
    }

    /**
     * Validate input length to prevent denial of service attacks.
     * 
     * @param input The input string to validate
     * @throws IllegalArgumentException if input is too long
     */
    public void validateInputLength(String input) {
        if (input != null && input.length() > 10000) { // 10KB limit
            throw new IllegalArgumentException("Input length exceeds maximum allowed size");
        }
    }

    /**
     * Sanitize and validate input for safe database storage.
     * 
     * @param input The input string to process
     * @return Sanitized and validated string
     * @throws SecurityException if security threats are detected
     */
    public String sanitizeAndValidate(String input) {
        if (input == null) {
            return null;
        }
        
        // First validate for security threats
        validateInput(input);
        
        // Then sanitize for safe output
        return sanitizeForOutput(input);
    }

    /**
     * Check if a string contains only safe characters for names (letters, spaces, hyphens, apostrophes).
     * 
     * @param input The input string to check
     * @return true if the input contains only safe characters
     */
    public boolean isSafeName(String input) {
        if (input == null || input.trim().isEmpty()) {
            return false;
        }
        
        return Pattern.matches("^[a-zA-ZäöüÄÖÜß\\s\\-']+$", input.trim());
    }

    /**
     * Check if a string contains only safe characters for usernames (letters, numbers, underscores).
     * 
     * @param input The input string to check
     * @return true if the input contains only safe characters
     */
    public boolean isSafeUsername(String input) {
        if (input == null || input.trim().isEmpty()) {
            return false;
        }
        
        return Pattern.matches("^[a-zA-Z0-9_]+$", input.trim());
    }

    /**
     * Validate URL format and safety.
     * 
     * @param url The URL string to validate
     * @return true if the URL is safe and valid
     */
    public boolean isSafeUrl(String url) {
        if (url == null || url.trim().isEmpty()) {
            return false;
        }
        
        // Basic URL validation
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            return false;
        }
        
        // Check for dangerous protocols or patterns
        String lowerUrl = url.toLowerCase();
        if (lowerUrl.contains("javascript:") || lowerUrl.contains("data:") || 
            lowerUrl.contains("vbscript:") || lowerUrl.contains("file:")) {
            return false;
        }
        
        return true;
    }
}