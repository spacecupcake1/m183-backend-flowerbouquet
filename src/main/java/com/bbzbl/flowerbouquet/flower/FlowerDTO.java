package com.bbzbl.flowerbouquet.flower;

import jakarta.validation.constraints.*;
import lombok.Data;
import org.hibernate.validator.constraints.URL;

/**
 * Data Transfer Object for Flower with validation annotations.
 */
@Data
public class FlowerDTO {
    
    private Long id;
    
    @NotBlank(message = "Flower name is required")
    @Size(min = 2, max = 100, message = "Flower name must be between 2 and 100 characters")
    @Pattern(regexp = "^[a-zA-ZäöüÄÖÜß\\s\\-']+$", message = "Flower name can only contain letters, spaces, hyphens, and apostrophes")
    private String name;
    
    @NotBlank(message = "Flower meaning is required")
    @Size(min = 5, max = 1000, message = "Flower meaning must be between 5 and 1000 characters")
    private String meaning;
    
    @NotBlank(message = "Availability status is required")
    @Pattern(regexp = "^(Available|Unavailable)$", message = "Availability must be either 'Available' or 'Unavailable'")
    private String availablity;
    
    @NotBlank(message = "Flower information is required")
    @Size(min = 10, max = 1000, message = "Flower information must be between 10 and 1000 characters")
    private String info;
    
    @NotBlank(message = "Flower color is required")
    @Size(min = 2, max = 100, message = "Flower color must be between 2 and 100 characters")
    @Pattern(regexp = "^[a-zA-ZäöüÄÖÜß\\s\\-]+$", message = "Flower color can only contain letters, spaces, and hyphens")
    private String color;
    
    @NotNull(message = "Price is required")
    @Min(value = 1, message = "Price must be at least 1")
    @Max(value = 9999, message = "Price cannot exceed 9999")
    private Integer price;
    
    @NotBlank(message = "Image URL is required")
    @Size(max = 500, message = "Image URL cannot exceed 500 characters")
    @URL(message = "Image URL must be a valid URL")
    private String imageUrl;
}