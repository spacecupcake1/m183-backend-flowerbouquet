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
        
        // FIXED: More targeted XSS detection - allows normal text content
        private static final Pattern XSS_PATTERN = Pattern.compile(
            ".*(<script[^>]*>.*?</script>|<script[^>]*/>|javascript:\\s*|vbscript:\\s*|" +
            "on(load|error|click|mouseover|focus|blur|change|submit)\\s*=|" +
            "<iframe[^>]*>|<object[^>]*>|<embed[^>]*>|<applet[^>]*>|" +
            "expression\\s*\\(|url\\s*\\(\\s*['\"]?javascript:|data:\\s*text/html).*",
            Pattern.CASE_INSENSITIVE | Pattern.DOTALL
        );

        @Override
        public boolean isValid(String value, ConstraintValidatorContext context) {
            if (value == null) return true;
            return !XSS_PATTERN.matcher(value).matches();
        }
    }
}