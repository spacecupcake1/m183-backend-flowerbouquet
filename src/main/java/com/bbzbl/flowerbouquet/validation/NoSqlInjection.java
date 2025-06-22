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

@Target({ElementType.FIELD, ElementType.PARAMETER})
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = NoSqlInjection.NoSqlInjectionValidator.class)
@Documented
public @interface NoSqlInjection {
    
    String message() default "Input contains potentially dangerous SQL patterns";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};

    class NoSqlInjectionValidator implements ConstraintValidator<NoSqlInjection, String> {
        
        // FIXED: More targeted SQL injection detection - allows apostrophes and hyphens in names
        private static final Pattern SQL_INJECTION_PATTERN = Pattern.compile(
            ".*(\\bDROP\\s+TABLE\\b|\\bDELETE\\s+FROM\\b|\\bINSERT\\s+INTO\\b|\\bUPDATE\\s+SET\\b|" +
            "\\bUNION\\s+SELECT\\b|\\bSELECT\\s+\\*\\s+FROM\\b|\\bOR\\s+1\\s*=\\s*1\\b|" +
            "\\bAND\\s+1\\s*=\\s*1\\b|;\\s*DROP\\b|;\\s*DELETE\\b|;\\s*INSERT\\b|" +
            "\\bEXEC\\s*\\(|\\bEXECUTE\\s*\\(|\\bSP_\\w+|\\bXP_\\w+|\\b0x[0-9a-f]+).*",
            Pattern.CASE_INSENSITIVE
        );

        @Override
        public void initialize(NoSqlInjection constraintAnnotation) {
            // No initialization needed
        }

        @Override
        public boolean isValid(String value, ConstraintValidatorContext context) {
            if (value == null) {
                return true;
            }
            
            // Check if the input contains SQL injection patterns
            boolean isValid = !SQL_INJECTION_PATTERN.matcher(value).matches();
            
            if (!isValid) {
                System.err.println("SQL Injection attempt detected: " + value);
            }
            
            return isValid;
        }
    }
}
