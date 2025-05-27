package com.bbzbl.flowerbouquet.flower;

import java.util.List;
import java.util.Optional;

import org.springframework.stereotype.Service;

@Service
public class FlowerService {
	
private final FlowerRepository flowerRepo;
	
	public  FlowerService(FlowerRepository flowerRepo) {
        this.flowerRepo = flowerRepo;
    }

	//Retrieves all flowers from the repository, ordered by name in ascending order.
    public List<Flower> getAllFlowers() {
        return flowerRepo.findByOrderByNameAsc();
    }
    
    //Retrieves a flower by its ID.
    public Optional<Flower> getFlowerById(Long id) {
        return flowerRepo.findById(id);
    }
    
    //Adds a list of flowers to the repository.
    public void addFlowers(List<Flower> flowers) {
    	flowerRepo.saveAll(flowers);
    }

    public List<Flower> searchFlowersByName(String name) {
        return flowerRepo.findByNameContainingIgnoreCase(name);
    }
    
    public List<Flower> getFlowersByAvailablity(String availablity) {
        return flowerRepo.findByAvailablity(availablity);
    }

}
