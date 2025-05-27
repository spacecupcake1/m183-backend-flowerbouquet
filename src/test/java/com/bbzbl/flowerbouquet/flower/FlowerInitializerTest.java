package com.bbzbl.flowerbouquet.flower;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.context.annotation.Import;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import({FlowerInitializer.class, FlowerService.class})
public class FlowerInitializerTest {

    @Autowired
    private FlowerRepository flowerRepository;

    // Method to set up necessary preconditions before each test
    @BeforeEach
    public void setUp() {
        // No specific setup required for this test
    }

    // Test to verify the initialization of flowers
    @Test
    public void testFlowerInitialization() {
        // Retrieve all flowers from the repository
        List<Flower> flowers = flowerRepository.findAll();

        // Assert that the flowers list is not empty
        assertThat(flowers).isNotEmpty();

        // Assert that the size of the flowers list is exactly 25
        assertThat(flowers).hasSize(25);

        // Find a flower with the name "Rose"
        Flower rose = flowers.stream()
                .filter(flower -> "Rose".equals(flower.getName()))
                .findFirst()
                .orElse(null);

        // Assert that the flower "Rose" is found
        assertThat(rose).isNotNull();

        // Assert that the meaning of the rose is "Love and Passion"
        assertThat(rose.getMeaning()).isEqualTo("Love and Passion");

        // Assert that the availability of the rose is between 30 and 70
        assertThat(rose.getAvailablity()).isEqualTo("yes");

        // Assert that the info about the rose is as expected
        assertThat(rose.getInfo()).isEqualTo("Roses are one of the most popular flowers in the world. They come in various colors and each color has its own meaning.");

        // Assert that the color of the rose is "Red"
        assertThat(rose.getColor()).isEqualTo("Red");

        // Assert that the price of the rose is 10
        assertThat(rose.getPrice()).isEqualTo(10);
    }
}
