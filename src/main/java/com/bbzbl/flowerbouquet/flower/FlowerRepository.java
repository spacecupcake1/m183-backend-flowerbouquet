package com.bbzbl.flowerbouquet.flower;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface FlowerRepository extends JpaRepository<Flower, Long> {
    
    List<Flower> findByOrderByNameAsc();
    List<Flower> findByNameContainingIgnoreCase(String name);
    List<Flower> findByAvailablity(String availablity);
    
    // Safe: Using @Query with parameters
    @Query("SELECT f FROM Flower f WHERE f.name LIKE :name AND f.availablity = :availablity")
    List<Flower> findByNameAndAvailablity(@Param("name") String name, @Param("availablity") String availablity);
    
    // Safe: Native query with parameters
    @Query(value = "SELECT * FROM flowers WHERE LOWER(name) LIKE LOWER(:searchTerm) AND price BETWEEN :minPrice AND :maxPrice", 
           nativeQuery = true)
    List<Flower> searchFlowersWithPriceRange(@Param("searchTerm") String searchTerm, 
                                           @Param("minPrice") Double minPrice, 
                                           @Param("maxPrice") Double maxPrice);
}

