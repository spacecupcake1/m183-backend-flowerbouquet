package com.bbzbl.flowerbouquet.flower;

import java.security.Principal;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.annotation.Validated;
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

import com.bbzbl.flowerbouquet.security.InputValidationService;
import com.bbzbl.flowerbouquet.security.SecurityAuditService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Enhanced REST Controller for flower operations with comprehensive security
 * FIXED: Added CORS support for frontend integration
 */
@RestController
@RequestMapping("/api/flowers")
@CrossOrigin(origins = "http://localhost:4200", allowCredentials = "true") // ADDED CORS
@Validated
public class FlowerController {

    private static final Logger logger = LoggerFactory.getLogger(FlowerController.class);

    @Autowired
    private FlowerService flowerService;

    @Autowired
    private InputValidationService inputValidationService;

    @Autowired
    private SecurityAuditService securityAuditService;

    /**
     * Get all flowers - accessible to authenticated users
     */
    @GetMapping
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<List<Flower>> getAllFlowers() {
        try {
            List<Flower> flowers = flowerService.getAllFlowers();
            logger.info("Retrieved {} flowers", flowers.size());
            return ResponseEntity.ok(flowers);
        } catch (Exception e) {
            logger.error("Error retrieving flowers: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * Get flower by ID - accessible to authenticated users
     */
    @GetMapping("/{id}")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<Flower> getFlowerById(@PathVariable @Min(1) Long id) {
        try {
            Optional<Flower> flower = flowerService.getFlowerById(id);
            if (flower.isPresent()) {
                logger.info("Retrieved flower with ID: {}", id);
                return ResponseEntity.ok(flower.get());
            } else {
                logger.warn("Flower with ID {} not found", id);
                return ResponseEntity.notFound().build();
            }
        } catch (Exception e) {
            logger.error("Error retrieving flower with ID {}: {}", id, e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * Search flowers by name - accessible to authenticated users
     */
    @GetMapping("/search")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<List<Flower>> searchFlowers(
            @RequestParam(required = false) @Size(min = 1, max = 100) String name,
            @RequestParam(required = false) @Size(min = 1, max = 50) String color,
            @RequestParam(required = false) String availability) {
        
        try {
            List<Flower> flowers;
            
            if (name != null && !name.trim().isEmpty()) {
                // Input validation
                inputValidationService.validateInput(name, "name");
                flowers = flowerService.searchFlowersByName(name.trim());
                logger.info("Search by name '{}' returned {} results", name, flowers.size());
            } else if (availability != null && !availability.trim().isEmpty()) {
                // Input validation
                inputValidationService.validateInput(availability, "availability");
                flowers = flowerService.getFlowersByAvailablity(availability.trim());
                logger.info("Search by availability '{}' returned {} results", availability, flowers.size());
            } else {
                // Return all flowers if no search criteria
                flowers = flowerService.getAllFlowers();
                logger.info("No search criteria provided, returning all {} flowers", flowers.size());
            }
            
            return ResponseEntity.ok(flowers);
            
        } catch (Exception e) {
            logger.error("Error searching flowers: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * Get flowers by availability status
     */
    @GetMapping("/availability/{status}")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<List<Flower>> getFlowersByAvailability(
            @PathVariable @NotBlank String status) {
        
        try {
            // Input validation
            inputValidationService.validateInput(status, "availability");
            
            List<Flower> flowers = flowerService.getFlowersByAvailablity(status);
            logger.info("Retrieved {} flowers with availability '{}'", flowers.size(), status);
            return ResponseEntity.ok(flowers);
            
        } catch (Exception e) {
            logger.error("Error retrieving flowers by availability '{}': {}", status, e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    // ========== ADMIN-ONLY ENDPOINTS ==========

    /**
     * Create new flower - ADMIN ONLY
     */
    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Flower> createFlower(@Valid @RequestBody FlowerCreateRequest flowerRequest,
                                             HttpServletRequest request,
                                             Principal principal) {
        
        String ipAddress = getClientIpAddress(request);
        String username = principal.getName();
        
        try {
            // Input validation
            inputValidationService.validateInput(flowerRequest.getName(), "name");
            inputValidationService.validateInput(flowerRequest.getMeaning(), "meaning");
            inputValidationService.validateInput(flowerRequest.getColor(), "color");
            inputValidationService.validateInput(flowerRequest.getInfo(), "info");
            
            // Convert DTO to entity
            Flower flower = new Flower();
            flower.setName(flowerRequest.getName().trim());
            flower.setMeaning(flowerRequest.getMeaning().trim());
            flower.setAvailablity(flowerRequest.getAvailability().trim()); // Note: backend uses 'availablity'
            flower.setInfo(flowerRequest.getInfo().trim());
            flower.setColor(flowerRequest.getColor().trim());
            flower.setPrice(flowerRequest.getPrice().intValue());
            flower.setImageUrl(flowerRequest.getImageUrl().trim());
            
            Flower createdFlower = flowerService.createFlower(flower);
            
            logger.info("Admin '{}' created flower '{}' from IP: {}", username, createdFlower.getName(), ipAddress);
            securityAuditService.logFlowerAction(username, "CREATE", createdFlower.getName(), ipAddress, true, null);
            
            return ResponseEntity.status(HttpStatus.CREATED).body(createdFlower);
            
        } catch (SecurityException e) {
            logger.warn("Security violation during flower creation by '{}' from IP {}: {}", username, ipAddress, e.getMessage());
            securityAuditService.logFlowerAction(username, "CREATE", "unknown", ipAddress, false, e.getMessage());
            return ResponseEntity.badRequest().build();
            
        } catch (Exception e) {
            logger.error("Error creating flower by '{}' from IP {}: {}", username, ipAddress, e.getMessage());
            securityAuditService.logFlowerAction(username, "CREATE", "unknown", ipAddress, false, e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * Update existing flower - ADMIN ONLY
     */
    @PutMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Flower> updateFlower(@PathVariable @Min(1) Long id,
                                             @Valid @RequestBody FlowerCreateRequest flowerRequest,
                                             HttpServletRequest request,
                                             Principal principal) {
        
        String ipAddress = getClientIpAddress(request);
        String username = principal.getName();
        
        try {
            // Input validation
            inputValidationService.validateInput(flowerRequest.getName(), "name");
            inputValidationService.validateInput(flowerRequest.getMeaning(), "meaning");
            inputValidationService.validateInput(flowerRequest.getColor(), "color");
            inputValidationService.validateInput(flowerRequest.getInfo(), "info");
            
            // Convert DTO to entity
            Flower flowerUpdate = new Flower();
            flowerUpdate.setName(flowerRequest.getName().trim());
            flowerUpdate.setMeaning(flowerRequest.getMeaning().trim());
            flowerUpdate.setAvailablity(flowerRequest.getAvailability().trim()); // Note: backend uses 'availablity'
            flowerUpdate.setInfo(flowerRequest.getInfo().trim());
            flowerUpdate.setColor(flowerRequest.getColor().trim());
            flowerUpdate.setPrice(flowerRequest.getPrice().intValue());
            flowerUpdate.setImageUrl(flowerRequest.getImageUrl().trim());
            
            Optional<Flower> updatedFlower = flowerService.updateFlower(id, flowerUpdate);
            
            if (updatedFlower.isPresent()) {
                logger.info("Admin '{}' updated flower '{}' (ID: {}) from IP: {}", username, updatedFlower.get().getName(), id, ipAddress);
                securityAuditService.logFlowerAction(username, "UPDATE", updatedFlower.get().getName(), ipAddress, true, null);
                return ResponseEntity.ok(updatedFlower.get());
            } else {
                logger.warn("Flower with ID {} not found for update by '{}' from IP: {}", id, username, ipAddress);
                securityAuditService.logFlowerAction(username, "UPDATE", "ID:" + id, ipAddress, false, "Flower not found");
                return ResponseEntity.notFound().build();
            }
            
        } catch (SecurityException e) {
            logger.warn("Security violation during flower update by '{}' from IP {}: {}", username, ipAddress, e.getMessage());
            securityAuditService.logFlowerAction(username, "UPDATE", "ID:" + id, ipAddress, false, e.getMessage());
            return ResponseEntity.badRequest().build();
            
        } catch (Exception e) {
            logger.error("Error updating flower ID {} by '{}' from IP {}: {}", id, username, ipAddress, e.getMessage());
            securityAuditService.logFlowerAction(username, "UPDATE", "ID:" + id, ipAddress, false, e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * Delete flower - ADMIN ONLY
     */
    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> deleteFlower(@PathVariable @Min(1) Long id,
                                        HttpServletRequest request,
                                        Principal principal) {
        
        String ipAddress = getClientIpAddress(request);
        String username = principal.getName();
        
        try {
            // Get flower name before deletion for logging
            Optional<Flower> flowerToDelete = flowerService.getFlowerById(id);
            String flowerName = flowerToDelete.map(Flower::getName).orElse("ID:" + id);
            
            boolean deleted = flowerService.deleteFlower(id);
            
            if (deleted) {
                logger.info("Admin '{}' deleted flower '{}' (ID: {}) from IP: {}", username, flowerName, id, ipAddress);
                securityAuditService.logFlowerAction(username, "DELETE", flowerName, ipAddress, true, null);
                return ResponseEntity.ok(Map.of("message", "Flower deleted successfully"));
            } else {
                logger.warn("Flower with ID {} not found for deletion by '{}' from IP: {}", id, username, ipAddress);
                securityAuditService.logFlowerAction(username, "DELETE", "ID:" + id, ipAddress, false, "Flower not found");
                return ResponseEntity.notFound().build();
            }
            
        } catch (Exception e) {
            logger.error("Error deleting flower ID {} by '{}' from IP {}: {}", id, username, ipAddress, e.getMessage());
            securityAuditService.logFlowerAction(username, "DELETE", "ID:" + id, ipAddress, false, e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * Get flower statistics - ADMIN ONLY
     */
    @GetMapping("/stats")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> getFlowerStatistics() {
        try {
            List<Flower> allFlowers = flowerService.getAllFlowers();
            
            long totalFlowers = allFlowers.size();
            long availableFlowers = allFlowers.stream()
                .filter(f -> "Available".equals(f.getAvailablity()))
                .count();
            long unavailableFlowers = totalFlowers - availableFlowers;
            
            Map<String, Object> stats = Map.of(
                "totalFlowers", totalFlowers,
                "availableFlowers", availableFlowers,
                "unavailableFlowers", unavailableFlowers,
                "availabilityPercentage", totalFlowers > 0 ? (availableFlowers * 100.0 / totalFlowers) : 0
            );
            
            return ResponseEntity.ok(stats);
            
        } catch (Exception e) {
            logger.error("Error retrieving flower statistics: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    // ========== UTILITY METHODS ==========

    /**
     * Extract client IP address from request.
     */
    private String getClientIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        
        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }
        
        return request.getRemoteAddr();
    }

    /**
     * DTO for flower creation/update requests
     */
    public static class FlowerCreateRequest {
        @NotBlank(message = "Name is required")
        @Size(min = 2, max = 100, message = "Name must be between 2 and 100 characters")
        private String name;

        @NotBlank(message = "Meaning is required")
        @Size(min = 5, max = 500, message = "Meaning must be between 5 and 500 characters")
        private String meaning;

        @NotBlank(message = "Availability is required")
        private String availability;

        @NotBlank(message = "Info is required")
        @Size(min = 10, max = 1000, message = "Info must be between 10 and 1000 characters")
        private String info;

        @NotBlank(message = "Color is required")
        @Size(min = 2, max = 50, message = "Color must be between 2 and 50 characters")
        private String color;

        @Min(value = 1, message = "Price must be at least 1")
        private Double price;

        @NotBlank(message = "Image URL is required")
        @Size(max = 500, message = "Image URL cannot exceed 500 characters")
        private String imageUrl;

        // Constructors, getters, setters
        public FlowerCreateRequest() {}

        public String getName() { return name; }
        public void setName(String name) { this.name = name; }

        public String getMeaning() { return meaning; }
        public void setMeaning(String meaning) { this.meaning = meaning; }

        public String getAvailability() { return availability; }
        public void setAvailability(String availability) { this.availability = availability; }

        public String getInfo() { return info; }
        public void setInfo(String info) { this.info = info; }

        public String getColor() { return color; }
        public void setColor(String color) { this.color = color; }

        public Double getPrice() { return price; }
        public void setPrice(Double price) { this.price = price; }

        public String getImageUrl() { return imageUrl; }
        public void setImageUrl(String imageUrl) { this.imageUrl = imageUrl; }
    }
}