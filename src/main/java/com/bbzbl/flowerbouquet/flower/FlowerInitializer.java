package com.bbzbl.flowerbouquet.flower;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Arrays;

@Configuration
public class FlowerInitializer {

    @Autowired
    private FlowerService flowerService;

    @Bean
    CommandLineRunner initDatabase() {
        return args -> {
            System.out.println("Initializing database with flowers");

            flowerService.addFlowers(Arrays.asList(
                new Flower(null, "Rose", "Love and Passion", "yes",
                    "Roses are one of the most popular flowers in the world. They come in various colors and each color has its own meaning.",
                    "Red", 10, "/images/Rose.jpg"),
                new Flower(null, "Tulip", "Perfect Love", "yes",
                    "Tulips are a symbol of perfect love. They are often associated with the Netherlands.",
                    "Yellow", 8, "/images/Tulip.jpg"),
                new Flower(null, "Lily", "Purity and Refined Beauty", "no",
                    "Lilies are known for their large, prominent flowers and pleasant fragrance.",
                    "White", 12, "/images/Lily.jpg"),
                // Add other flowers similarly
                new Flower(null, "Daisy", "Innocence and Purity", "yes",
                    "Daisies are simple yet sophisticated flowers that symbolize innocence and purity.",
                    "White", 5, "/images/Daisy.jpg"),
                new Flower(null, "Orchid", "Beauty and Strength", "yes",
                    "Orchids are exotic flowers that represent beauty, strength, and luxury.",
                    "Purple", 15, "/images/Orchid.jpg"),
                new Flower(null, "Sunflower", "Adoration and Loyalty", "yes",
                    "Sunflowers are known for their large size and bright yellow petals, symbolizing adoration and loyalty.",
                    "Yellow", 7, "/images/Sunflower.jpg"),
                new Flower(null, "Peony", "Romance and Prosperity", "no",
                    "Peonies are lush, full flowers that are often used in wedding bouquets.",
                    "Pink", 20, "/images/Peony.jpg"),
                new Flower(null, "Carnation", "Love and Fascination", "yes",
                    "Carnations are versatile flowers with a ruffled appearance, symbolizing love and fascination.",
                    "Red", 6, "/images/Carnation.jpg"),
                new Flower(null, "Chrysanthemum", "Joy and Optimism", "no",
                    "Chrysanthemums are bright, cheerful flowers that bloom in a variety of colors.",
                    "Orange", 9, "/images/Chrysanthemum.jpg"),
                new Flower(null, "Hydrangea", "Gratitude and Grace", "yes",
                    "Hydrangeas are large, round flowers that come in many colors, representing gratitude and grace.",
                    "Blue", 18, "/images/Hydrangea.jpg"),
                new Flower(null, "Lavender", "Calm and Serenity", "no",
                    "Lavender is known for its soothing fragrance and is often used in aromatherapy.",
                    "Purple", 10, "/images/Lavender.jpg"),
                new Flower(null, "Marigold", "Passion and Creativity", "yes",
                    "Marigolds are bright flowers that symbolize passion and creativity.",
                    "Orange", 4, "/images/Marigold.jpg"),
                new Flower(null, "Iris", "Wisdom and Valor", "yes",
                    "Irises are named after the Greek goddess Iris and represent wisdom and valor.",
                    "Blue", 11, "/images/Iris.jpg"),
                new Flower(null, "Daffodil", "Rebirth and New Beginnings", "no",
                    "Daffodils are bright yellow flowers that symbolize rebirth and new beginnings.",
                    "Yellow", 5, "/images/Daffodil.jpg"),
                new Flower(null, "Anemone", "Protection and Anticipation", "yes",
                    "Anemones are delicate flowers that are often associated with protection and anticipation.",
                    "Red", 8, "/images/Anemone.jpg"),
                new Flower(null, "Bluebell", "Humility and Gratitude", "yes",
                    "Bluebells are small, bell-shaped flowers that symbolize humility and gratitude.",
                    "Blue", 9, "/images/Bluebell.jpg"),
                new Flower(null, "Gardenia", "Purity and Sweetness", "no",
                    "Gardenias are fragrant, white flowers that represent purity and sweetness.",
                    "White", 12, "/images/Gardenia.jpg"),
                new Flower(null, "Camellia", "Adoration and Devotion", "yes",
                    "Camellias are beautiful, layered flowers that symbolize adoration and devotion.",
                    "Pink", 13, "/images/Camellia.jpg"),
                new Flower(null, "Poppy", "Remembrance and Imagination", "no",
                    "Poppies are vibrant flowers that are often associated with remembrance and imagination.",
                    "Red", 6, "/images/Poppy.jpg"),
                new Flower(null, "Zinnia", "Lasting Affection", "yes",
                    "Zinnias are bright, cheerful flowers that symbolize lasting affection.",
                    "Mixed", 7, "/images/Zinnia.jpg"),
                new Flower(null, "Begonia", "Cordiality", "no",
                    "Begonias are known for their bright colors and symbolize cordiality.",
                    "Pink", 9, "/images/Begonia.jpg"),
                new Flower(null, "Cosmos", "Harmony and Peace", "yes",
                    "Cosmos are daisy-like flowers that represent harmony and peace.",
                    "Pink", 8, "/images/Cosmos.jpg"),
                new Flower(null, "Dahlia", "Elegance and Dignity", "no",
                    "Dahlias are bushy, tuberous flowers that symbolize elegance and dignity.",
                    "Purple", 14, "/images/Dahlia.jpg"),
                new Flower(null, "Freesia", "Innocence and Friendship", "yes",
                    "Freesias are fragrant flowers that represent innocence and friendship.",
                    "White", 10, "/images/Freesia.jpg"),
                new Flower(null, "Gladiolus", "Strength and Integrity", "no",
                    "Gladiolus are tall flowers that symbolize strength and integrity.",
                    "Red", 7, "/images/Gladiolus.jpg")
            ));
        };
    }
}
