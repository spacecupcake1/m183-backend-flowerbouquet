package com.bbzbl.flowerbouquet.flower;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.bbzbl.flowerbouquet.user.User;
import com.bbzbl.flowerbouquet.user.UserService;

/**
 * REST controller for managing flowers.
 */
@RestController
@CrossOrigin(origins = "http://localhost:4200")
@RequestMapping("/api/flowers")
public class FlowerController {

    private final FlowerService flowerService;
    private final FlowerTempService flowerTempService;
    private final UserService userService;

    /**
     * Constructor for FlowerController.
     */
    @Autowired
    public FlowerController(FlowerService flowerService, FlowerTempService flowerTempService, UserService userService) {
        this.flowerService = flowerService;
        this.flowerTempService = flowerTempService;
        this.userService = userService;
    }

    // ========== PUBLIC ENDPOINTS ==========

    /**
     * GET /api/flowers : Get all flowers.
     */
    @GetMapping
    public List<Flower> getAllFlowers() {
        return flowerService.getAllFlowers();
    }

    /**
     * GET /api/flowers/{id} : Get a flower by its ID.
     */
    @GetMapping("/{id}")
    public ResponseEntity<Flower> getFlowerById(@PathVariable Long id) {
        return flowerService.getFlowerById(id)
                .map(flower -> ResponseEntity.ok().body(flower))
                .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/search")
    public List<Flower> searchFlowersByName(@RequestParam String name) {
        return flowerService.searchFlowersByName(name);
    }
    
    @GetMapping("/filter")
    public ResponseEntity<List<Flower>> filterFlowers(@RequestParam String availablity) {
        List<Flower> flowers = flowerService.getFlowersByAvailablity(availablity);
        return ResponseEntity.ok(flowers);
    }

    // ========== USER FLOWER CUSTOMIZATION (CART) ENDPOINTS ==========

    /**
     * POST /api/flowers/customize : Add a flower to temporary storage.
     */
    @PostMapping("/customize")
    public ResponseEntity<Map<String, String>> addFlowerToTemp(@RequestBody Flower flower) {
        flowerTempService.addFlowerToTemp(flower);
        Map<String, String> response = new HashMap<>();
        response.put("message", "Flower added to temporary storage");
        return ResponseEntity.ok(response);
    }

    /**
     * GET /api/flowers/customize : Retrieve all flowers from temporary storage.
     */
    @GetMapping("/customize")
    public ResponseEntity<List<Flower>> getTempFlowers() {
        return ResponseEntity.ok(flowerTempService.getTempFlowers());
    }

    /**
     * GET /api/flowers/customize/total-price : Calculate the total price of all flowers in temporary storage.
     */
    @GetMapping("/customize/total-price")
    public ResponseEntity<Integer> getTotalPrice() {
        int totalPrice = flowerTempService.calculateTotalPrice();
        return ResponseEntity.ok(totalPrice);
    }

    /**
     * GET /api/flowers/customize/clear : Clear all flowers from temporary storage.
     */
    @GetMapping("/customize/clear")
    public ResponseEntity<String> clearTempFlowers() {
        flowerTempService.clearTempFlowers();
        return ResponseEntity.ok("Temporary flower storage cleared");
    }

    /**
     * POST /api/flowers/customize/delivery : Enable or disable the delivery charge.
     */
    @PostMapping("/customize/delivery")
    public ResponseEntity<String> setDeliveryOption(@RequestBody boolean enable) {
        flowerTempService.setDeliveryEnabled(enable);
        return ResponseEntity.ok("Delivery option has been " + (enable ? "enabled" : "disabled"));
    }

    // ========== ADMIN-ONLY ENDPOINTS ==========

    /**
     * POST /api/flowers : Create a new flower (Admin only).
     */
    @PostMapping
    public ResponseEntity<?> createFlower(@RequestBody Flower flower, @RequestParam Long userId) {
        // Check if user is admin
        if (!isUserAdmin(userId)) {
            return ResponseEntity.status(403).body(createErrorResponse("Access denied. Admin privileges required."));
        }

        try {
            Flower createdFlower = flowerService.createFlower(flower);
            return ResponseEntity.status(201).body(createdFlower);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(createErrorResponse("Failed to create flower: " + e.getMessage()));
        }
    }

    /**
     * PUT /api/flowers/{id} : Update an existing flower (Admin only).
     */
    @PutMapping("/{id}")
    public ResponseEntity<?> updateFlower(@PathVariable Long id, @RequestBody Flower flower, @RequestParam Long userId) {
        // Check if user is admin
        if (!isUserAdmin(userId)) {
            return ResponseEntity.status(403).body(createErrorResponse("Access denied. Admin privileges required."));
        }

        Optional<Flower> updatedFlower = flowerService.updateFlower(id, flower);
        if (updatedFlower.isPresent()) {
            return ResponseEntity.ok(updatedFlower.get());
        } else {
            return ResponseEntity.notFound().build();
        }
    }

    /**
     * DELETE /api/flowers/{id} : Delete a flower (Admin only).
     */
    @DeleteMapping("/{id}")
    public ResponseEntity<?> deleteFlower(@PathVariable Long id, @RequestParam Long userId) {
        // Check if user is admin
        if (!isUserAdmin(userId)) {
            return ResponseEntity.status(403).body(createErrorResponse("Access denied. Admin privileges required."));
        }

        if (flowerService.deleteFlower(id)) {
            Map<String, String> response = new HashMap<>();
            response.put("message", "Flower deleted successfully");
            return ResponseEntity.ok(response);
        } else {
            return ResponseEntity.notFound().build();
        }
    }

    /**
     * GET /api/flowers/admin/stats : Get flower statistics (Admin only).
     */
    @GetMapping("/admin/stats")
    public ResponseEntity<?> getFlowerStats(@RequestParam Long userId) {
        // Check if user is admin
        if (!isUserAdmin(userId)) {
            return ResponseEntity.status(403).body(createErrorResponse("Access denied. Admin privileges required."));
        }

        Map<String, Object> stats = new HashMap<>();
        stats.put("totalFlowers", flowerService.getFlowerCount());
        stats.put("availableFlowers", flowerService.getFlowersByAvailablity("Available").size());
        stats.put("unavailableFlowers", flowerService.getFlowersByAvailablity("Unavailable").size());
        
        return ResponseEntity.ok(stats);
    }

    /**
     * POST /api/flowers/admin/bulk : Bulk create flowers (Admin only).
     */
    @PostMapping("/admin/bulk")
    public ResponseEntity<?> bulkCreateFlowers(@RequestBody List<Flower> flowers, @RequestParam Long userId) {
        // Check if user is admin
        if (!isUserAdmin(userId)) {
            return ResponseEntity.status(403).body(createErrorResponse("Access denied. Admin privileges required."));
        }

        try {
            List<Flower> createdFlowers = flowerService.addFlowers(flowers);
            Map<String, Object> response = new HashMap<>();
            response.put("message", "Bulk flower creation successful");
            response.put("created", createdFlowers.size());
            response.put("flowers", createdFlowers);
            return ResponseEntity.status(201).body(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(createErrorResponse("Failed to create flowers: " + e.getMessage()));
        }
    }

    /**
     * Check if a user has admin privileges.
     */
    private boolean isUserAdmin(Long userId) {
        if (userId == null) {
            return false;
        }
        
        Optional<User> user = userService.getUserById(userId);
        return user.isPresent() && userService.isAdmin(user.get());
    }

    /**
     * Create a standardized error response.
     */
    private Map<String, String> createErrorResponse(String message) {
        Map<String, String> response = new HashMap<>();
        response.put("error", message);
        return response;
    }
}