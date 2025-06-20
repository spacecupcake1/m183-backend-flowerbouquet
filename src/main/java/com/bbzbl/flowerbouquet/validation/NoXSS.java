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
@Constraint(validatedBy = NoXSS.NoXSSValidator.class)
@Documented
public @interface NoXSS {
    String message() default "Input contains potentially dangerous XSS patterns";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};

    class NoXSSValidator implements ConstraintValidator<NoXSS, String> {
        private static final Pattern XSS_PATTERN = Pattern.compile(
            ".*(<script|javascript:|on\\w+\\s*=|<iframe|<object|<embed|<form|<input|<meta|<link).*",
            Pattern.CASE_INSENSITIVE | Pattern.DOTALL
        );

        @Override
        public boolean isValid(String value, ConstraintValidatorContext context) {
            if (value == null) return true;
            return !XSS_PATTERN.matcher(value).matches();
        }
    }
}