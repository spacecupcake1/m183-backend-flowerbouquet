package com.bbzbl.flowerbouquet.flower;

import java.util.Arrays;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

/**
 * Initializes the database with sample flower data.
 * This class implements CommandLineRunner to run after the application starts.
 */
@Component
public class FlowerInitializer implements CommandLineRunner {

    @Autowired
    private FlowerService flowerService;

    @Override
    public void run(String... args) throws Exception {
        // Only initialize if no flowers exist
        if (flowerService.getFlowerCount() == 0) {
            System.out.println("Initializing database with flowers");
            initializeFlowers();
        } else {
            System.out.println("Database already contains flowers, skipping initialization");
        }
    }

    private void initializeFlowers() {
        List<Flower> flowers = Arrays.asList(
            new Flower(null, 
                "Rose", 
                "Symbol of love and passion", 
                "Available", 
                "Classic red roses are perfect for expressing deep love and romantic feelings. These beautiful flowers have been cherished for centuries.", 
                "Red", 
                25, 
                "https://images.unsplash.com/photo-1518895949257-7621c3c786d7"),
            
            new Flower(null, 
                "Tulip", 
                "Symbol of perfect love and elegance", 
                "Available", 
                "Elegant tulips represent perfect love and are associated with spring and new beginnings. Available in many beautiful colors.", 
                "Yellow", 
                15, 
                "https://images.unsplash.com/photo-1520637836862-4d197d17c91a"),
            
            new Flower(null, 
                "Sunflower", 
                "Symbol of loyalty and devotion", 
                "Available", 
                "Bright and cheerful sunflowers represent loyalty, devotion, and adoration. Their large, vibrant blooms bring joy to any bouquet.", 
                "Yellow", 
                20, 
                "https://images.unsplash.com/photo-1597848212624-e7ddc00f9b6e"),
            
            new Flower(null, 
                "Lily", 
                "Symbol of purity and rebirth", 
                "Available", 
                "Elegant lilies symbolize purity, rebirth, and motherhood. These sophisticated flowers are perfect for special occasions.", 
                "White", 
                30, 
                "https://images.unsplash.com/photo-1544889304-647743d0a0b8"),
            
            new Flower(null, 
                "Carnation", 
                "Symbol of fascination and distinction", 
                "Available", 
                "Carnations represent fascination, distinction, and love. These long-lasting flowers come in many colors and are perfect for arrangements.", 
                "Pink", 
                12, 
                "https://images.unsplash.com/photo-1582794543249-1e6ba4fb2103"),
            
            new Flower(null, 
                "Daisy", 
                "Symbol of innocence and new beginnings", 
                "Available", 
                "Sweet daisies represent innocence, new beginnings, and true love. These cheerful flowers bring a sense of freshness to any bouquet.", 
                "White", 
                10, 
                "https://images.unsplash.com/photo-1574684891174-df6b02ab38d7"),
            
            new Flower(null, 
                "Orchid", 
                "Symbol of luxury and strength", 
                "Unavailable", 
                "Exotic orchids represent luxury, strength, and beauty. These sophisticated flowers are highly prized for their unique appearance.", 
                "Purple", 
                50, 
                "https://images.unsplash.com/photo-1553406830-ef2513450d76"),
            
            new Flower(null, 
                "Peony", 
                "Symbol of honor and wealth", 
                "Available", 
                "Luxurious peonies symbolize honor, wealth, and a happy life. These full, fragrant flowers are perfect for creating stunning arrangements.", 
                "Pink", 
                40, 
                "https://images.unsplash.com/photo-1588840647282-e3d1a3b4da5e"),
            
            new Flower(null, 
                "Iris", 
                "Symbol of wisdom and valor", 
                "Available", 
                "Elegant irises represent wisdom, valor, and faith. These distinctive flowers add sophistication to any floral arrangement.", 
                "Blue", 
                22, 
                "https://images.unsplash.com/photo-1566207474742-de921626ad0c"),
            
            new Flower(null, 
                "Hydrangea", 
                "Symbol of gratitude and understanding", 
                "Available", 
                "Beautiful hydrangeas represent heartfelt gratitude and understanding. These full, rounded blooms create stunning focal points in arrangements.", 
                "Blue", 
                35, 
                "https://images.unsplash.com/photo-1592717147028-62589b25d0bd")
        );

        try {
            flowerService.addFlowers(flowers);
            System.out.println("Successfully initialized " + flowers.size() + " flowers in the database");
        } catch (Exception e) {
            System.err.println("Error initializing flowers: " + e.getMessage());
            e.printStackTrace();
        }
    }
}