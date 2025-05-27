package com.bbzbl.flowerbouquet.flower;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface FlowerRepository extends JpaRepository<Flower, Long> {
    List<Flower> findByOrderByNameAsc();
    List<Flower> findByNameContainingIgnoreCase(String name);
    List<Flower> findByAvailablity(String availablity);
}

