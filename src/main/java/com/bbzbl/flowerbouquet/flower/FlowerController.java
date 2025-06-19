package com.bbzbl.flowerbouquet.flower;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
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

import com.bbzbl.flowerbouquet.security.InputSanitizer;
import com.bbzbl.flowerbouquet.security.InputValidationService;
import com.bbzbl.flowerbouquet.user.User;
import com.bbzbl.flowerbouquet.user.UserService;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;

/**
 * REST controller for managing flowers with comprehensive input validation.
 */
@RestController
@CrossOrigin(origins = "http://localhost:4200")
@RequestMapping("/api/flowers")
@Validated
public class FlowerController {

    private final FlowerService flowerService;
    private final FlowerTempService flowerTempService;
    private final UserService userService;
    private final InputSanitizer inputSanitizer;

    @Autowired
    public FlowerController(FlowerService flowerService, FlowerTempService flowerTempService, 
                           UserService userService, InputSanitizer inputSanitizer) {
        this.flowerService = flowerService;
        this.flowerTempService = flowerTempService;
        this.userService = userService;
        this.inputSanitizer = inputSanitizer;
    }

     @Autowired
    private InputValidationService validationService;

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
    public ResponseEntity<Flower> getFlowerById(
            @PathVariable @NotNull @Min(1) Long id) {
        
        return flowerService.getFlowerById(id)
                .map(flower -> ResponseEntity.ok().body(flower))
                .orElse(ResponseEntity.notFound().build());
    }

    /**
     * GET /api/flowers/search : Search flowers by name.
     */
    @GetMapping("/search")
    public List<Flower> searchFlowersByName(
            @RequestParam @NotNull String name) {
        
        // Validate and sanitize search input
        inputSanitizer.validateInput(name);
        String sanitizedName = inputSanitizer.sanitizeForOutput(name);
        
        if (sanitizedName.length() < 2 || sanitizedName.length() > 100) {
            throw new IllegalArgumentException("Search term must be between 2 and 100 characters");
        }
        
        return flowerService.searchFlowersByName(sanitizedName);
    }
    
    /**
     * GET /api/flowers/filter : Filter flowers by availability.
     */
    @GetMapping("/filter")
    public ResponseEntity<List<Flower>> filterFlowers(
            @RequestParam @NotNull String availablity) {
        
        // Validate availability parameter
        if (!availablity.equals("Available") && !availablity.equals("Unavailable")) {
            throw new IllegalArgumentException("Availability must be 'Available' or 'Unavailable'");
        }
        
        List<Flower> flowers = flowerService.getFlowersByAvailablity(availablity);
        return ResponseEntity.ok(flowers);
    }

    // ========== USER FLOWER CUSTOMIZATION (CART) ENDPOINTS ==========

    /**
     * POST /api/flowers/customize : Add a flower to temporary storage.
     */
    @PostMapping("/customize")
    public ResponseEntity<Map<String, String>> addFlowerToTemp(@Valid @RequestBody Flower flower) {
        // Additional validation for flower object
        validateFlowerForTempStorage(flower);
        
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
     * GET /api/flowers/customize/total-price : Calculate total price.
     */
    @GetMapping("/customize/total-price")
    public ResponseEntity<Integer> getTotalPrice() {
        int totalPrice = flowerTempService.calculateTotalPrice();
        return ResponseEntity.ok(totalPrice);
    }

    /**
     * GET /api/flowers/customize/clear : Clear temporary storage.
     */
    @GetMapping("/customize/clear")
    public ResponseEntity<String> clearTempFlowers() {
        flowerTempService.clearTempFlowers();
        return ResponseEntity.ok("Temporary flower storage cleared");
    }

    /**
     * POST /api/flowers/customize/delivery : Set delivery option.
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
    public ResponseEntity<?> createFlower(@Valid @RequestBody FlowerDTO flowerDTO, 
                                        @RequestParam Long userId) {
        
        // Validate and sanitize all inputs
        validationService.validateInput(flowerDTO.getName(), "name");
        validationService.validateInput(flowerDTO.getMeaning(), "meaning");
        validationService.validateInput(flowerDTO.getInfo(), "info");
        
        // Sanitize inputs before processing
        flowerDTO.setName(validationService.sanitizeInput(flowerDTO.getName()));
        flowerDTO.setMeaning(validationService.sanitizeInput(flowerDTO.getMeaning()));
        flowerDTO.setInfo(validationService.sanitizeInput(flowerDTO.getInfo()));
        
        // Process flower creation...
        Flower flower = flowerService.createFlower(convertDtoToEntity(flowerDTO));
        
        // Return sanitized output
        return ResponseEntity.ok(flower);
    }

    /**
     * PUT /api/flowers/{id} : Update an existing flower (Admin only).
     */
    @PutMapping("/{id}")
    public ResponseEntity<?> updateFlower(
            @PathVariable @NotNull @Min(1) Long id, 
            @Valid @RequestBody FlowerDTO flowerDTO, 
            @RequestParam @NotNull @Min(1) Long userId) {
        
        // Check admin privileges
        if (!isUserAdmin(userId)) {
            return ResponseEntity.status(403).body(createErrorResponse("Access denied. Admin privileges required."));
        }

        try {
            // Convert DTO to Entity with additional validation
            Flower flower = convertDtoToEntity(flowerDTO);
            flower.setId(id); // Ensure the ID matches the path parameter
            validateAndSanitizeFlower(flower);
            
            Optional<Flower> updatedFlower = flowerService.updateFlower(id, flower);
            if (updatedFlower.isPresent()) {
                return ResponseEntity.ok(updatedFlower.get());
            } else {
                return ResponseEntity.notFound().build();
            }
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(createErrorResponse("Failed to update flower: " + e.getMessage()));
        }
    }

    /**
     * DELETE /api/flowers/{id} : Delete a flower (Admin only).
     */
    @DeleteMapping("/{id}")
    public ResponseEntity<?> deleteFlower(
            @PathVariable @NotNull @Min(1) Long id, 
            @RequestParam @NotNull @Min(1) Long userId) {
        
        // Check admin privileges
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
    public ResponseEntity<?> getFlowerStats(@RequestParam @NotNull @Min(1) Long userId) {
        // Check admin privileges
        if (!isUserAdmin(userId)) {
            return ResponseEntity.status(403).body(createErrorResponse("Access denied. Admin privileges required."));
        }

        Map<String, Object> stats = new HashMap<>();
        stats.put("totalFlowers", flowerService.getFlowerCount());
        stats.put("availableFlowers", flowerService.getFlowersByAvailablity("Available").size());
        stats.put("unavailableFlowers", flowerService.getFlowersByAvailablity("Unavailable").size());
        
        return ResponseEntity.ok(stats);
    }

    // ========== HELPER METHODS ==========

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
        response.put("error", inputSanitizer.sanitizeForOutput(message));
        return response;
    }

    /**
     * Convert FlowerDTO to Flower entity.
     */
    private Flower convertDtoToEntity(FlowerDTO dto) {
        Flower flower = new Flower();
        flower.setId(dto.getId());
        flower.setName(dto.getName());
        flower.setMeaning(dto.getMeaning());
        flower.setAvailablity(dto.getAvailablity());
        flower.setInfo(dto.getInfo());
        flower.setColor(dto.getColor());
        flower.setPrice(dto.getPrice());
        flower.setImageUrl(dto.getImageUrl());
        return flower;
    }

    /**
     * Validate and sanitize flower data.
     */
    private void validateAndSanitizeFlower(Flower flower) {
        // Validate all string fields for security threats
        inputSanitizer.validateInput(flower.getName());
        inputSanitizer.validateInput(flower.getMeaning());
        inputSanitizer.validateInput(flower.getInfo());
        inputSanitizer.validateInput(flower.getColor());

        // Validate URL safety
        if (!inputSanitizer.isSafeUrl(flower.getImageUrl())) {
            throw new IllegalArgumentException("Invalid or unsafe image URL");
        }

        // Sanitize text fields
        flower.setName(inputSanitizer.sanitizeForOutput(flower.getName()));
        flower.setMeaning(inputSanitizer.sanitizeForOutput(flower.getMeaning()));
        flower.setInfo(inputSanitizer.sanitizeForOutput(flower.getInfo()));
        flower.setColor(inputSanitizer.sanitizeForOutput(flower.getColor()));
    }

    /**
     * Additional validation for flowers being added to temporary storage.
     */
    private void validateFlowerForTempStorage(Flower flower) {
        if (flower.getId() == null || flower.getId() <= 0) {
            throw new IllegalArgumentException("Invalid flower ID");
        }
        
        // Verify the flower exists in the database
        if (!flowerService.existsById(flower.getId())) {
            throw new IllegalArgumentException("Flower does not exist");
        }
    }
}