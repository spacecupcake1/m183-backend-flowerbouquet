package com.bbzbl.flowerbouquet.flower;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
@Entity
public class Flower {
	
    public Flower() {}

    public Flower(Long id, String name, String meaning, String availablity, String info, String color, int price, String imageUrl) {
        this.id = id;
        this.name = name;
        this.meaning = meaning;
        this.availablity = availablity;
        this.info = info;
        this.color = color;
        this.price = price;
        this.imageUrl = imageUrl;
    }
    
    @Id
    @GeneratedValue(strategy= GenerationType.IDENTITY)
    private Long id;
    
    @Column(length = 100, nullable = false)
    @NotBlank(message = "Flower name is required")
    @Size(min = 2, max = 100, message = "Flower name must be between 2 and 100 characters")
    @Pattern(regexp = "^[a-zA-ZäöüÄÖÜß\\s\\-']+$", message = "Flower name can only contain letters, spaces, hyphens, and apostrophes")
    private String name;
    
    @Column(length = 1000)
    @NotBlank(message = "Flower meaning is required")
    @Size(min = 5, max = 1000, message = "Flower meaning must be between 5 and 1000 characters")
    private String meaning;
    
    @Column(length = 100)
    @NotBlank(message = "Availability status is required")
    @Pattern(regexp = "^(Available|Unavailable)$", message = "Availability must be either 'Available' or 'Unavailable'")
    private String availablity;
     
    @Column(length = 1000)
    @NotBlank(message = "Flower information is required")
    @Size(min = 10, max = 1000, message = "Flower information must be between 10 and 1000 characters")
    private String info;
    
    @Column(length = 100, nullable = false)
    @NotBlank(message = "Flower color is required")
    @Size(min = 2, max = 100, message = "Flower color must be between 2 and 100 characters")
    @Pattern(regexp = "^[a-zA-ZäöüÄÖÜß\\s\\-]+$", message = "Flower color can only contain letters, spaces, and hyphens")
    private String color;
    
    @Column(nullable = false)
    @NotNull(message = "Price is required")
    @Min(value = 1, message = "Price must be at least 1")
    @Max(value = 9999, message = "Price cannot exceed 9999")
    private int price;
    
    // FIXED: Removed @URL annotation and updated pattern to allow relative paths
    @Column(length = 500, nullable = false)
    @NotBlank(message = "Image URL is required")
    @Size(max = 500, message = "Image URL cannot exceed 500 characters")
    @Pattern(
        regexp = "^(https?://.*|images/[a-zA-Z0-9._-]+\\.(jpg|jpeg|png|gif|webp|svg))$", 
        message = "Image URL must be a valid HTTP/HTTPS URL or relative path like 'images/filename.jpg'"
    )
    private String imageUrl;
}