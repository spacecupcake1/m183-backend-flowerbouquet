package com.bbzbl.flowerbouquet.exception;

import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.ConstraintViolationException;

@RestControllerAdvice
@Component("alternativeExceptionHandler") 
public class GlobalExceptionHandler {

    private static final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    /**
     * Handle validation errors from @Valid annotations
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, Object>> handleValidationExceptions(
            MethodArgumentNotValidException ex, HttpServletRequest request) {
        
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getAllErrors().forEach((error) -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();
            errors.put(fieldName, errorMessage);
        });

        // Log security validation failures
        logger.warn("Validation failed for request to {} from IP {}: {}", 
                   request.getRequestURI(), 
                   request.getRemoteAddr(), 
                   errors);

        Map<String, Object> response = new HashMap<>();
        response.put("error", "Validation failed");
        response.put("details", errors);
        response.put("status", HttpStatus.BAD_REQUEST.value());

        return ResponseEntity.badRequest().body(response);
    }

    /**
     * Handle constraint violations (e.g., from method-level validation)
     */
    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<Map<String, Object>> handleConstraintViolationException(
            ConstraintViolationException ex, HttpServletRequest request) {
        
        Map<String, String> errors = new HashMap<>();
        ex.getConstraintViolations().forEach(violation -> {
            String propertyPath = violation.getPropertyPath().toString();
            String message = violation.getMessage();
            errors.put(propertyPath, message);
        });

        // Log security constraint violations
        logger.warn("Constraint violation for request to {} from IP {}: {}", 
                   request.getRequestURI(), 
                   request.getRemoteAddr(), 
                   errors);

        Map<String, Object> response = new HashMap<>();
        response.put("error", "Constraint violation");
        response.put("details", errors);
        response.put("status", HttpStatus.BAD_REQUEST.value());

        return ResponseEntity.badRequest().body(response);
    }

    /**
     * Handle security exceptions
     */
    @ExceptionHandler(SecurityException.class)
    public ResponseEntity<Map<String, Object>> handleSecurityException(
            SecurityException ex, HttpServletRequest request) {
        
        // Log security violations
        logger.error("Security violation for request to {} from IP {}: {}", 
                    request.getRequestURI(), 
                    request.getRemoteAddr(), 
                    ex.getMessage());

        Map<String, Object> response = new HashMap<>();
        response.put("error", "Security violation detected");
        response.put("message", "Your request contains potentially dangerous content");
        response.put("status", HttpStatus.BAD_REQUEST.value());

        return ResponseEntity.badRequest().body(response);
    }

    /**
     * Handle illegal arguments (including validation failures)
     */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, Object>> handleIllegalArgumentException(
            IllegalArgumentException ex, HttpServletRequest request) {
        
        logger.warn("Illegal argument for request to {} from IP {}: {}", 
                   request.getRequestURI(), 
                   request.getRemoteAddr(), 
                   ex.getMessage());

        Map<String, Object> response = new HashMap<>();
        response.put("error", "Invalid input");
        response.put("message", ex.getMessage());
        response.put("status", HttpStatus.BAD_REQUEST.value());

        return ResponseEntity.badRequest().body(response);
    }
}