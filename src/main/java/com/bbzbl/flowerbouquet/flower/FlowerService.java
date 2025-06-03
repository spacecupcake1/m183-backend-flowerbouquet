package com.bbzbl.flowerbouquet.flower;

import java.util.List;
import java.util.Optional;

import org.springframework.stereotype.Service;

@Service
public class FlowerService {
	
    private final FlowerRepository flowerRepo;
	
    public FlowerService(FlowerRepository flowerRepo) {
        this.flowerRepo = flowerRepo;
    }
    
    /**
     * Retrieves all flowers from the repository, ordered by name in ascending order.
     */
    public List<Flower> getAllFlowers() {
        return flowerRepo.findByOrderByNameAsc();
    }
    
    /**
     * Retrieves a flower by its ID.
     */
    public Optional<Flower> getFlowerById(Long id) {
        return flowerRepo.findById(id);
    }
    
    /**
     * Search flowers by name (case-insensitive).
     */
    public List<Flower> searchFlowersByName(String name) {
        return flowerRepo.findByNameContainingIgnoreCase(name);
    }
    
    /**
     * Get flowers by availability status.
     */
    public List<Flower> getFlowersByAvailablity(String availablity) {
        return flowerRepo.findByAvailablity(availablity);
    }

    // ========== ADMIN-ONLY OPERATIONS ==========
    
    /**
     * Creates a new flower (Admin only).
     */
    public Flower createFlower(Flower flower) {
        // Ensure ID is null for new flowers
        flower.setId(null);
        return flowerRepo.save(flower);
    }
    
    /**
     * Updates an existing flower (Admin only).
     */
    public Optional<Flower> updateFlower(Long id, Flower flowerDetails) {
        return flowerRepo.findById(id).map(existingFlower -> {
            // Update all fields
            existingFlower.setName(flowerDetails.getName());
            existingFlower.setMeaning(flowerDetails.getMeaning());
            existingFlower.setAvailablity(flowerDetails.getAvailablity());
            existingFlower.setInfo(flowerDetails.getInfo());
            existingFlower.setColor(flowerDetails.getColor());
            existingFlower.setPrice(flowerDetails.getPrice());
            existingFlower.setImageUrl(flowerDetails.getImageUrl());
            
            return flowerRepo.save(existingFlower);
        });
    }
    
    /**
     * Deletes a flower by ID (Admin only).
     */
    public boolean deleteFlower(Long id) {
        if (flowerRepo.existsById(id)) {
            flowerRepo.deleteById(id);
            return true;
        }
        return false;
    }
    
    /**
     * Adds a list of flowers to the repository (Admin only - for bulk operations).
     */
    public List<Flower> addFlowers(List<Flower> flowers) {
        return flowerRepo.saveAll(flowers);
    }

    /**
     * Check if a flower exists by ID.
     */
    public boolean existsById(Long id) {
        return flowerRepo.existsById(id);
    }

    /**
     * Get total count of flowers.
     */
    public long getFlowerCount() {
        return flowerRepo.count();
    }
}