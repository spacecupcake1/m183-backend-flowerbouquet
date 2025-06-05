package com.bbzbl.flowerbouquet.flower;

import java.util.Arrays;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

/**
 * Initializes the database with sample flower data using local images.
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
                "images/Rose.jpg"),
            
            new Flower(null, 
                "Tulip", 
                "Symbol of perfect love and elegance", 
                "Available", 
                "Elegant tulips represent perfect love and are associated with spring and new beginnings. Available in many beautiful colors.", 
                "Yellow", 
                15, 
                "images/Tulip.jpg"),
            
            new Flower(null, 
                "Sunflower", 
                "Symbol of loyalty and devotion", 
                "Available", 
                "Bright and cheerful sunflowers represent loyalty, devotion, and adoration. Their large, vibrant blooms bring joy to any bouquet.", 
                "Yellow", 
                20, 
                "images/Sunflower.jpg"),
            
            new Flower(null, 
                "Lily", 
                "Symbol of purity and rebirth", 
                "Available", 
                "Elegant lilies symbolize purity, rebirth, and motherhood. These sophisticated flowers are perfect for special occasions.", 
                "White", 
                30, 
                "images/Lily.jpg"),
            
            new Flower(null, 
                "Carnation", 
                "Symbol of fascination and distinction", 
                "Available", 
                "Carnations represent fascination, distinction, and love. These long-lasting flowers come in many colors and are perfect for arrangements.", 
                "Pink", 
                12, 
                "images/Carnation.jpg"),
            
            new Flower(null, 
                "Daisy", 
                "Symbol of innocence and new beginnings", 
                "Available", 
                "Sweet daisies represent innocence, new beginnings, and true love. These cheerful flowers bring a sense of freshness to any bouquet.", 
                "White", 
                10, 
                "images/Daisy.jpg"),
            
            new Flower(null, 
                "Orchid", 
                "Symbol of luxury and strength", 
                "Unavailable", 
                "Exotic orchids represent luxury, strength, and beauty. These sophisticated flowers are highly prized for their unique appearance.", 
                "Purple", 
                50, 
                "images/Orchid.jpg"),
            
            new Flower(null, 
                "Peony", 
                "Symbol of honor and wealth", 
                "Available", 
                "Luxurious peonies symbolize honor, wealth, and a happy life. These full, fragrant flowers are perfect for creating stunning arrangements.", 
                "Pink", 
                40, 
                "images/Peony.jpg"),
            
            new Flower(null, 
                "Iris", 
                "Symbol of wisdom and valor", 
                "Available", 
                "Elegant irises represent wisdom, valor, and faith. These distinctive flowers add sophistication to any floral arrangement.", 
                "Blue", 
                22, 
                "images/Iris.jpg"),
            
            new Flower(null, 
                "Hydrangea", 
                "Symbol of gratitude and understanding", 
                "Available", 
                "Beautiful hydrangeas represent heartfelt gratitude and understanding. These full, rounded blooms create stunning focal points in arrangements.", 
                "Blue", 
                35, 
                "images/Hydrangea.jpg"),
            
            // Additional flowers using your available images
            new Flower(null, 
                "Lavender", 
                "Symbol of serenity and grace", 
                "Available", 
                "Fragrant lavender represents serenity, grace, and calmness. These aromatic purple flowers are perfect for creating peaceful arrangements.", 
                "Purple", 
                18, 
                "images/Lavender.jpg"),
            
            new Flower(null, 
                "Marigold", 
                "Symbol of passion and creativity", 
                "Available", 
                "Vibrant marigolds represent passion, creativity, and positive emotions. These bright orange flowers add warmth to any bouquet.", 
                "Orange", 
                14, 
                "images/Marigold.jpg"),
            
            new Flower(null, 
                "Poppy", 
                "Symbol of remembrance and peace", 
                "Available", 
                "Delicate poppies symbolize remembrance, peace, and eternal sleep. These colorful flowers are meaningful and beautiful.", 
                "Red", 
                16, 
                "images/Poppy.jpg"),
            
            new Flower(null, 
                "Zinnia", 
                "Symbol of thoughts of friends", 
                "Available", 
                "Cheerful zinnias represent thoughts of friends and lasting affection. These vibrant flowers bloom all season long.", 
                "Mixed", 
                12, 
                "images/Zinnia.jpg"),
            
            new Flower(null, 
                "Dahlia", 
                "Symbol of elegance and dignity", 
                "Available", 
                "Stunning dahlias represent elegance, dignity, and commitment. These full, geometric flowers create impressive focal points.", 
                "Pink", 
                28, 
                "images/Dahlia.jpg"),
            
            new Flower(null, 
                "Cosmos", 
                "Symbol of order and harmony", 
                "Available", 
                "Delicate cosmos represent order, harmony, and peaceful love. These simple yet beautiful flowers add grace to arrangements.", 
                "Pink", 
                11, 
                "images/Cosmos.jpg"),
            
            new Flower(null, 
                "Freesia", 
                "Symbol of friendship and trust", 
                "Available", 
                "Fragrant freesias symbolize friendship, trust, and thoughtfulness. These elegant flowers are perfect for expressing appreciation.", 
                "White", 
                24, 
                "images/Freesia.jpg"),
            
            new Flower(null, 
                "Gladiolus", 
                "Symbol of strength and victory", 
                "Available", 
                "Tall gladiolus represent strength, victory, and moral integrity. These impressive flowers make bold statements in arrangements.", 
                "Pink", 
                26, 
                "images/Gladiolus.jpg"),
            
            new Flower(null, 
                "Daffodil", 
                "Symbol of new beginnings", 
                "Available", 
                "Bright daffodils herald new beginnings, rebirth, and eternal life. These cheerful spring flowers bring hope and joy.", 
                "Yellow", 
                13, 
                "images/Daffodil.jpg"),
            
            new Flower(null, 
                "Gardenia", 
                "Symbol of purity and sweetness", 
                "Available", 
                "Fragrant gardenias represent purity, sweetness, and secret love. These creamy white flowers are highly prized for their scent.", 
                "White", 
                32, 
                "images/Gardenia.jpg")
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