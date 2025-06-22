package com.bbzbl.flowerbouquet.validation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.regex.Pattern;

import jakarta.validation.Constraint;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import jakarta.validation.Payload;

/**
 * Custom validation annotation to prevent SQL injection attacks
 */
@Target({ElementType.FIELD, ElementType.PARAMETER})
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = NoSqlInjection.NoSqlInjectionValidator.class)
@Documented
public @interface NoSqlInjection {
    
    String message() default "Input contains potentially dangerous SQL patterns";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};

    /**
     * Validator implementation for SQL injection detection
     */
    class NoSqlInjectionValidator implements ConstraintValidator<NoSqlInjection, String> {
        
        // Pattern to detect common SQL injection attempts
        private static final Pattern SQL_INJECTION_PATTERN = Pattern.compile(
            ".*('|(\\-\\-)|(;)|(\\|)|(\\*)|(%)|(\\bOR\\b)|(\\bAND\\b)|(\\bUNION\\b)|(\\bSELECT\\b)|" +
            "(\\bINSERT\\b)|(\\bDELETE\\b)|(\\bUPDATE\\b)|(\\bDROP\\b)|(\\bCREATE\\b)|(\\bALTER\\b)|" +
            "(\\bEXEC\\b)|(\\bEXECUTE\\b)|(\\bSP_\\w+)|(\\bXP_\\w+)|(\\b0x[0-9a-f]+)).*",
            Pattern.CASE_INSENSITIVE
        );

        @Override
        public void initialize(NoSqlInjection constraintAnnotation) {
            // No initialization needed
        }

        @Override
        public boolean isValid(String value, ConstraintValidatorContext context) {
            // Null values are considered valid (use @NotNull for null checks)
            if (value == null) {
                return true;
            }
            
            // Check if the input contains SQL injection patterns
            boolean isValid = !SQL_INJECTION_PATTERN.matcher(value).matches();
            
            if (!isValid) {
                // Log the security violation
                System.err.println("SQL Injection attempt detected: " + value);
            }
            
            return isValid;
        }
    }
}