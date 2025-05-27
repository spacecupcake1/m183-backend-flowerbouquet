package com.bbzbl.flowerbouquet.flower;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.*;

public class FlowerServiceTest {

    @Mock
    private FlowerRepository flowerRepo;

    @InjectMocks
    private FlowerService flowerService;

    @BeforeEach
    public void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    public void testGetAllFlowers() {
        // Create a list of flowers to be returned by the mocked FlowerRepository
        List<Flower> flowers = Arrays.asList(new Flower(1L, "Lotus", "Enlightenment and Purity", "yes", 
                "The lotus flower is often associated with purity, spiritual awakening, and enlightenment. It is a symbol of purity and rebirth, rising clean from the mud.",
                "Pink", 12, "https://example.com/images/lotus.jpg"));
        
        // Define the behavior of the mocked findByOrderByNameAsc method
        when(flowerRepo.findByOrderByNameAsc()).thenReturn(flowers);

        // Call the method to be tested
        List<Flower> result = flowerService.getAllFlowers();
        
        // Assert that the result is as expected
        assertThat(result).hasSize(1);
        assertThat(result.get(0).getName()).isEqualTo("Lotus");

        // Verify that the findByOrderByNameAsc method was called exactly once
        verify(flowerRepo, times(1)).findByOrderByNameAsc();
    }

    @Test
    public void testGetFlowerById() {
        // Create a flower object to be returned by the mocked FlowerRepository
        Flower flower = new Flower(1L, "Lotus", "Enlightenment and Purity", "yes", 
                "The lotus flower is often associated with purity, spiritual awakening, and enlightenment. It is a symbol of purity and rebirth, rising clean from the mud.",
                "Pink", 12, "https://example.com/images/lotus.jpg");
        
        // Define the behavior of the mocked findById method
        when(flowerRepo.findById(1L)).thenReturn(Optional.of(flower));

        // Call the method to be tested
        Optional<Flower> result = flowerService.getFlowerById(1L);
        
        // Assert that the result is as expected
        assertThat(result).isPresent();
        assertThat(result.get().getName()).isEqualTo("Lotus");

        // Verify that the findById method was called exactly once with the specified ID
        verify(flowerRepo, times(1)).findById(1L);
    }

    @Test
    public void testAddFlowers() {
        // Create a list of flowers to be saved by the service
        List<Flower> flowers = Arrays.asList(new Flower(1L, "Lotus", "Enlightenment and Purity", "yes", 
                "The lotus flower is often associated with purity, spiritual awakening, and enlightenment. It is a symbol of purity and rebirth, rising clean from the mud.",
                "Pink", 12, "https://example.com/images/lotus.jpg"));
        
        // Call the method to be tested
        flowerService.addFlowers(flowers);

        // Verify that the saveAll method was called exactly once with the list of flowers
        verify(flowerRepo, times(1)).saveAll(anyList());
    }
}