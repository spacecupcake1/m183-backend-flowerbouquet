package com.bbzbl.flowerbouquet.flower;

import java.math.BigDecimal;

import com.bbzbl.flowerbouquet.validation.NoSqlInjection;
import com.bbzbl.flowerbouquet.validation.NoXSS;

import jakarta.validation.constraints.DecimalMax;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * Fixed FlowerDTO with correct field names and relaxed validation
 */
public class FlowerDTO {

    private Long id;

    @NotBlank(message = "Flower name is required")
    @Size(min = 2, max = 100, message = "Flower name must be between 2 and 100 characters")
    @Pattern(regexp = "^[a-zA-ZäöüÄÖÜß0-9\\s\\-'.,()]+$", message = "Flower name contains invalid characters")
    @NoSqlInjection
    @NoXSS
    private String name;

    @Size(max = 1000, message = "Meaning must not exceed 1000 characters")
    @NoSqlInjection
    @NoXSS
    private String meaning;

    @NotBlank(message = "Availability is required")
    @Pattern(regexp = "^(Available|Unavailable)$", message = "Availability must be either 'Available' or 'Unavailable'")
    private String availability; // FIXED: Changed from 'availablity' to 'availability'

    @Size(max = 1000, message = "Info must not exceed 1000 characters")
    @NoSqlInjection
    @NoXSS
    private String info;

    @NotBlank(message = "Color is required")
    @Size(min = 2, max = 50, message = "Color must be between 2 and 50 characters")
    @Pattern(regexp = "^[a-zA-ZäöüÄÖÜß\\s\\-,]+$", message = "Color contains invalid characters")
    @NoSqlInjection
    @NoXSS
    private String color;

    @NotNull(message = "Price is required")
    @DecimalMin(value = "0.01", message = "Price must be greater than 0")
    @DecimalMax(value = "9999.99", message = "Price must not exceed 9999.99")
    private BigDecimal price;

    @Size(max = 500, message = "Image URL must not exceed 500 characters")
    private String imageUrl;

    // Default constructor
    public FlowerDTO() {}

    // Constructor with all fields
    public FlowerDTO(String name, String meaning, String availability, String info, 
                    String color, BigDecimal price, String imageUrl) {
        this.name = name;
        this.meaning = meaning;
        this.availability = availability; // FIXED
        this.info = info;
        this.color = color;
        this.price = price;
        this.imageUrl = imageUrl;
    }

    // Getters and setters with proper trimming
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name != null ? name.trim() : null;
    }

    public String getMeaning() {
        return meaning;
    }

    public void setMeaning(String meaning) {
        this.meaning = meaning != null ? meaning.trim() : null;
    }

    public String getAvailability() { // FIXED method name
        return availability;
    }

    public void setAvailability(String availability) { // FIXED method name and parameter
        this.availability = availability != null ? availability.trim() : null;
    }

    // DEPRECATED: Keep for backward compatibility, remove after testing
    @Deprecated
    public String getAvailablity() {
        return availability;
    }

    @Deprecated
    public void setAvailablity(String availablity) {
        this.availability = availablity != null ? availablity.trim() : null;
    }

    public String getInfo() {
        return info;
    }

    public void setInfo(String info) {
        this.info = info != null ? info.trim() : null;
    }

    public String getColor() {
        return color;
    }

    public void setColor(String color) {
        this.color = color != null ? color.trim() : null;
    }

    public BigDecimal getPrice() {
        return price;
    }

    public void setPrice(BigDecimal price) {
        this.price = price;
    }

    public String getImageUrl() {
        return imageUrl;
    }

    public void setImageUrl(String imageUrl) {
        this.imageUrl = imageUrl != null ? imageUrl.trim() : null;
    }
}