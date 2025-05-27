package com.bbzbl.flowerbouquet.flower;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.validation.constraints.NotEmpty;
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
    @Size(max = 100)
    @NotEmpty
    private String name;
    
    @Column(length = 1000)
    @Size(max = 100)
    @NotEmpty
    private String meaning;
    
    @Column(length = 100)
    @Size(max = 100)
    @NotEmpty
    private String availablity;
     
    @Column(length = 1000)
    @Size(max = 1000)
    @NotEmpty
    private String info;
    
    @Column(length = 100, nullable = false)
    @Size(max = 100)
    @NotEmpty
    private String color;
    
    @Column(length = 100, nullable = false)
    @Size(max = 100)
    @NotEmpty
    private int price;
    
    @Column(length = 100, nullable = false)
    @Size(max = 100)
    @NotEmpty
    private String imageUrl;

}