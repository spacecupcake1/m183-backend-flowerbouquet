package com.bbzbl.flowerbouquet.validation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import jakarta.validation.Constraint;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import jakarta.validation.Payload;

@Target({ElementType.FIELD, ElementType.PARAMETER})
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = StrongPassword.StrongPasswordValidator.class)
@Documented
public @interface StrongPassword {
    String message() default "Password must be at least 8 characters with uppercase, lowercase, number and special character";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};

    class StrongPasswordValidator implements ConstraintValidator<StrongPassword, String> {
        @Override
        public boolean isValid(String password, ConstraintValidatorContext context) {
            if (password == null) return false;
            
            // FIXED: More reasonable password requirements
            return password.length() >= 8 &&
                   password.matches(".*[A-Z].*") &&                    // At least one uppercase
                   password.matches(".*[a-z].*") &&                    // At least one lowercase  
                   password.matches(".*[0-9].*") &&                    // At least one number
                   password.matches(".*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>\\/?~`].*"); // At least one special char
        }
    }
}