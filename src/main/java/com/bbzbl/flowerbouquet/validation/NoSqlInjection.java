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
        private static final Pattern SQL_INJECTION_PATTERN = Pattern.compile(
            ".*('|(\\-\\-)|(;)|(\\|)|(\\*)|(%)|(\\bOR\\b)|(\\bAND\\b)|(\\bUNION\\b)|(\\bSELECT\\b)|(\\bINSERT\\b)|(\\bDELETE\\b)|(\\bUPDATE\\b)|(\\bDROP\\b)|(\\bCREATE\\b)|(\\bALTER\\b)).*",
            Pattern.CASE_INSENSITIVE
        );

        @Override
        public boolean isValid(String value, ConstraintValidatorContext context) {
            if (value == null) return true;
            return !SQL_INJECTION_PATTERN.matcher(value).matches();
        }
    }
}
