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
@Constraint(validatedBy = SecureInput.SecureInputValidator.class)
@Documented
public @interface SecureInput {
    String message() default "Input contains potentially dangerous content";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
    
    SecurityValidationService.InputType inputType() default SecurityValidationService.InputType.GENERIC;

    class SecureInputValidator implements ConstraintValidator<SecureInput, String> {
        
        private SecurityValidationService.InputType inputType;

        @Override
        public void initialize(SecureInput constraintAnnotation) {
            this.inputType = constraintAnnotation.inputType();
        }

        @Override
        public boolean isValid(String value, ConstraintValidatorContext context) {
            if (value == null) return true;

            // Use the validation service
            SecurityValidationService validationService = new SecurityValidationService();
            SecurityValidationService.ValidationResult result = 
                validationService.validateInput(value, "field", inputType);

            if (!result.isValid()) {
                context.disableDefaultConstraintViolation();
                context.buildConstraintViolationWithTemplate(result.getFirstError())
                       .addConstraintViolation();
                return false;
            }

            return true;
        }
    }
}