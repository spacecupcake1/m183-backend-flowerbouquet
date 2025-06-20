package com.bbzbl.flowerbouquet.flower;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.ResponseEntity;

public class FlowerControllerTest {

    @Mock
    private FlowerService flowerService;  // Mock FlowerService to simulate its behavior

    @InjectMocks
    private FlowerController flowerController;  // Inject the mocks into FlowerController

    @BeforeEach
    public void setUp() {
        // Initialize the mock objects before each test
        MockitoAnnotations.openMocks(this);
    }

    @Test
    public void testGetAllFlowers() {
        // Create a list of flowers to be returned by the mocked FlowerService
        List<Flower> flowers = Arrays.asList(new Flower(1L, "Lotus", "Enlightenment and Purity", "yes", 
                "The lotus flower is often associated with purity, spiritual awakening, and enlightenment. It is a symbol of purity and rebirth, rising clean from the mud.",
                "Pink", 12, "https://example.com/images/lotus.jpg"));
        
        // Define the behavior of the mocked getAllFlowers method
        when(flowerService.getAllFlowers()).thenReturn(flowers);

        // Call the method to be tested
        ResponseEntity<List<Flower>> response = flowerController.getAllFlowers();
        List<Flower> result = response.getBody();
        
        // Assert that the result is as expected
        assertThat(result).hasSize(1);
        assertThat(result.get(0).getName()).isEqualTo("Lotus");

        // Verify that the getAllFlowers method was called exactly once
        verify(flowerService, times(1)).getAllFlowers();
    }

    @Test
    public void testGetFlowerById() {
        // Create a flower object to be returned by the mocked FlowerService
        Flower flower = new Flower(1L, "Lotus", "Enlightenment and Purity", "yes", 
                "The lotus flower is often associated with purity, spiritual awakening, and enlightenment. It is a symbol of purity and rebirth, rising clean from the mud.",
                "Pink", 12, "https://example.com/images/lotus.jpg");
        
        // Define the behavior of the mocked getFlowerById method
        when(flowerService.getFlowerById(1L)).thenReturn(Optional.of(flower));

        // Call the method to be tested
        ResponseEntity<Flower> response = flowerController.getFlowerById(1L);
        
        // Assert that the response status code is 200 (OK)
        assertThat(response.getStatusCodeValue()).isEqualTo(200);
        
        // Assert that the body of the response is not null and contains the expected flower
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getName()).isEqualTo("Lotus");

        // Verify that the getFlowerById method was called exactly once with the specified ID
        verify(flowerService, times(1)).getFlowerById(1L);
    }
}
