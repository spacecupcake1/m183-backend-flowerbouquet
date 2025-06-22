package com.bbzbl.flowerbouquet.flower;

import java.math.BigDecimal;

import jakarta.validation.constraints.DecimalMax;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

/**
 * Simplified FlowerDTO for debugging validation issues
 */
public class FlowerDTO {

    private Long id;

    @NotBlank(message = "Flower name is required")
    @Size(min = 2, max = 100, message = "Flower name must be between 2 and 100 characters")
    private String name;

    @Size(max = 255, message = "Meaning must not exceed 255 characters")
    private String meaning;

    @NotBlank(message = "Availability is required")
    private String availablity; // Note: keeping original spelling to match backend

    @Size(max = 1000, message = "Info must not exceed 1000 characters")
    private String info;

    @NotBlank(message = "Color is required")
    @Size(min = 2, max = 30, message = "Color must be between 2 and 30 characters")
    private String color;

    @NotNull(message = "Price is required")
    @DecimalMin(value = "0.01", message = "Price must be greater than 0")
    @DecimalMax(value = "9999.99", message = "Price must not exceed 9999.99")
    private BigDecimal price;

    @Size(max = 255, message = "Image URL must not exceed 255 characters")
    private String imageUrl;

    // Default constructor
    public FlowerDTO() {}

    // Constructor with all fields
    public FlowerDTO(String name, String meaning, String availablity, String info, 
                    String color, BigDecimal price, String imageUrl) {
        this.name = name;
        this.meaning = meaning;
        this.availablity = availablity;
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

    public String getAvailablity() {
        return availablity;
    }

    public void setAvailablity(String availablity) {
        this.availablity = availablity != null ? availablity.trim() : null;
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

    @Override
    public String toString() {
        return "FlowerDTO{" +
                "id=" + id +
                ", name='" + name + '\'' +
                ", meaning='" + meaning + '\'' +
                ", availablity='" + availablity + '\'' +
                ", info='" + info + '\'' +
                ", color='" + color + '\'' +
                ", price=" + price +
                ", imageUrl='" + imageUrl + '\'' +
                '}';
    }
}