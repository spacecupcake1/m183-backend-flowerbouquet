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
@Constraint(validatedBy = SafeFilename.SafeFilenameValidator.class)
@Documented
public @interface SafeFilename {
    String message() default "Filename contains dangerous characters";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};

    class SafeFilenameValidator implements ConstraintValidator<SafeFilename, String> {
        private static final Pattern DANGEROUS_FILENAME_PATTERN = Pattern.compile(
            ".*(\\.\\.|[<>:\"|?*\\\\\\x00-\\x1f]).*"
        );

        @Override
        public boolean isValid(String value, ConstraintValidatorContext context) {
            if (value == null) return true;
            return !DANGEROUS_FILENAME_PATTERN.matcher(value).matches();
        }
    }
}