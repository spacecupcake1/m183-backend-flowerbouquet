package com.bbzbl.flowerbouquet.flower;

import com.bbzbl.flowerbouquet.validation.NoSqlInjection;
import com.bbzbl.flowerbouquet.validation.NoXSS;
import com.bbzbl.flowerbouquet.validation.SafeFilename;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public class FlowerCreateDTO {

    @NotBlank(message = "Flower name is required")
    @Size(min = 2, max = 100, message = "Flower name must be between 2 and 100 characters")
    @Pattern(regexp = "^[a-zA-ZäöüÄÖÜß\\s\\-']+$", message = "Flower name can only contain letters, spaces, hyphens, and apostrophes")
    @NoSqlInjection
    @NoXSS
    private String name;

    @NotBlank(message = "Flower meaning is required")
    @Size(min = 5, max = 1000, message = "Flower meaning must be between 5 and 1000 characters")
    @NoSqlInjection
    @NoXSS
    private String meaning;

    @NotBlank(message = "Availability status is required")
    @Pattern(regexp = "^(Available|Unavailable)$", message = "Availability must be either 'Available' or 'Unavailable'")
    @NoSqlInjection
    @NoXSS
    private String availability;

    @NotBlank(message = "Flower information is required")
    @Size(min = 10, max = 1000, message = "Flower information must be between 10 and 1000 characters")
    @NoSqlInjection
    @NoXSS
    private String info;

    @NotBlank(message = "Flower color is required")
    @Size(min = 2, max = 100, message = "Flower color must be between 2 and 100 characters")
    @Pattern(regexp = "^[a-zA-ZäöüÄÖÜß\\s\\-]+$", message = "Flower color can only contain letters, spaces, and hyphens")
    @NoSqlInjection
    @NoXSS
    private String color;

    @NotNull(message = "Price is required")
    @Min(value = 1, message = "Price must be at least 1")
    @Max(value = 9999, message = "Price cannot exceed 9999")
    private Integer price;

    @NotBlank(message = "Image URL is required")
    @Size(max = 500, message = "Image URL cannot exceed 500 characters")
    @Pattern(
        regexp = "^(https?://.*|images/[a-zA-Z0-9._-]+\\.(jpg|jpeg|png|gif|webp))$",
        message = "Image URL must be a valid HTTP(S) URL or relative path to images folder"
    )
    @SafeFilename
    @NoSqlInjection
    @NoXSS
    private String imageUrl;

    // Constructors, getters, and setters
    public FlowerCreateDTO() {}

    // Getters and setters
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getMeaning() { return meaning; }
    public void setMeaning(String meaning) { this.meaning = meaning; }

    public String getAvailability() { return availability; }
    public void setAvailability(String availability) { this.availability = availability; }

    public String getInfo() { return info; }
    public void setInfo(String info) { this.info = info; }

    public String getColor() { return color; }
    public void setColor(String color) { this.color = color; }

    public Integer getPrice() { return price; }
    public void setPrice(Integer price) { this.price = price; }

    public String getImageUrl() { return imageUrl; }
    public void setImageUrl(String imageUrl) { this.imageUrl = imageUrl; }
}
