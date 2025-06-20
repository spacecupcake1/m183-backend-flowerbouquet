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
 */
@RestController
@RequestMapping("/api/flowers")
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
            return flower.map(ResponseEntity::ok)
                        .orElse(ResponseEntity.notFound().build());
        } catch (Exception e) {
            logger.error("Error retrieving flower with ID {}: {}", id, e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * Search flowers by name - accessible to authenticated users with input validation
     */
    @GetMapping("/search")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<?> searchFlowers(
            @RequestParam @NotBlank @Size(min = 1, max = 100) String name,
            HttpServletRequest request,
            Principal principal) {
        
        String ipAddress = getClientIpAddress(request);
        String username = principal.getName();
        
        try {
            // Validate search input for security
            inputValidationService.validateSearchInput(name);
            inputValidationService.validateInput(name, "search");
            
            List<Flower> flowers = flowerService.searchFlowersByName(name);
            
            return ResponseEntity.ok(flowers);
            
        } catch (IllegalArgumentException e) {
            logger.warn("Invalid search input from user '{}' at IP {}: {}", username, ipAddress, e.getMessage());
            securityAuditService.logSecurityViolation(username, "INVALID_SEARCH", e.getMessage(), ipAddress);
            
            return ResponseEntity.badRequest().body(Map.of(
                "error", "Invalid search term",
                "message", "Search term contains invalid characters"
            ));
        } catch (Exception e) {
            logger.error("Error searching flowers for user '{}': {}", username, e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * Create new flower - ADMIN ONLY with comprehensive validation and auditing
     */
    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> createFlower(
            @Valid @RequestBody FlowerCreateDTO flowerDTO,
            HttpServletRequest request,
            Principal principal) {
        
        String ipAddress = getClientIpAddress(request);
        String username = principal.getName();
        
        try {
            // Additional security validation beyond @Valid
            inputValidationService.validateInput(flowerDTO.getName(), "name");
            inputValidationService.validateInput(flowerDTO.getMeaning(), "meaning");
            inputValidationService.validateInput(flowerDTO.getInfo(), "info");
            
            // Convert DTO to entity
            Flower flower = new Flower();
            flower.setName(flowerDTO.getName());
            flower.setMeaning(flowerDTO.getMeaning());
            flower.setAvailablity(flowerDTO.getAvailability());
            flower.setInfo(flowerDTO.getInfo());
            flower.setColor(flowerDTO.getColor());
            flower.setPrice(flowerDTO.getPrice());
            flower.setImageUrl(flowerDTO.getImageUrl());
            
            Flower savedFlower = flowerService.createFlower(flower);
            
            // Log successful creation
            securityAuditService.logFlowerAction(username, "CREATE", savedFlower.getName(), ipAddress, true, null);
            
            logger.info("Flower '{}' created by admin '{}' from IP: {}", 
                       savedFlower.getName(), username, ipAddress);
            
            return ResponseEntity.status(HttpStatus.CREATED).body(savedFlower);
            
        } catch (SecurityException e) {
            securityAuditService.logFlowerAction(username, "CREATE", flowerDTO.getName(), ipAddress, false, e.getMessage());
            securityAuditService.logSecurityViolation(username, "FLOWER_CREATE_VIOLATION", e.getMessage(), ipAddress);
            
            return ResponseEntity.badRequest().body(Map.of(
                "error", "Security violation",
                "message", "Input contains potentially dangerous content"
            ));
            
        } catch (Exception e) {
            logger.error("Error creating flower by admin '{}': {}", username, e.getMessage());
            securityAuditService.logFlowerAction(username, "CREATE", flowerDTO.getName(), ipAddress, false, e.getMessage());
            
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of(
                "error", "Failed to create flower"
            ));
        }
    }

    /**
     * Update flower - ADMIN ONLY with comprehensive validation and auditing
     */
    @PutMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> updateFlower(
            @PathVariable @Min(1) Long id,
            @Valid @RequestBody FlowerCreateDTO flowerDTO,
            HttpServletRequest request,
            Principal principal) {
        
        String ipAddress = getClientIpAddress(request);
        String username = principal.getName();
        
        try {
            // Check if flower exists
            if (!flowerService.existsById(id)) {
                return ResponseEntity.notFound().build();
            }
            
            // Additional security validation
            inputValidationService.validateInput(flowerDTO.getName(), "name");
            inputValidationService.validateInput(flowerDTO.getMeaning(), "meaning");
            inputValidationService.validateInput(flowerDTO.getInfo(), "info");
            
            // Convert DTO to entity
            Flower flower = new Flower();
            flower.setName(flowerDTO.getName());
            flower.setMeaning(flowerDTO.getMeaning());
            flower.setAvailablity(flowerDTO.getAvailability());
            flower.setInfo(flowerDTO.getInfo());
            flower.setColor(flowerDTO.getColor());
            flower.setPrice(flowerDTO.getPrice());
            flower.setImageUrl(flowerDTO.getImageUrl());
            
            Optional<Flower> updatedFlower = flowerService.updateFlower(id, flower);
            
            if (updatedFlower.isPresent()) {
                // Log successful update
                securityAuditService.logFlowerAction(username, "UPDATE", updatedFlower.get().getName(), ipAddress, true, null);
                
                logger.info("Flower '{}' (ID: {}) updated by admin '{}' from IP: {}", 
                           updatedFlower.get().getName(), id, username, ipAddress);
                
                return ResponseEntity.ok(updatedFlower.get());
            } else {
                return ResponseEntity.notFound().build();
            }
            
        } catch (SecurityException e) {
            securityAuditService.logFlowerAction(username, "UPDATE", flowerDTO.getName(), ipAddress, false, e.getMessage());
            securityAuditService.logSecurityViolation(username, "FLOWER_UPDATE_VIOLATION", e.getMessage(), ipAddress);
            
            return ResponseEntity.badRequest().body(Map.of(
                "error", "Security violation",
                "message", "Input contains potentially dangerous content"
            ));
            
        } catch (Exception e) {
            logger.error("Error updating flower {} by admin '{}': {}", id, username, e.getMessage());
            securityAuditService.logFlowerAction(username, "UPDATE", flowerDTO.getName(), ipAddress, false, e.getMessage());
            
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of(
                "error", "Failed to update flower"
            ));
        }
    }

    /**
     * Delete flower - ADMIN ONLY with auditing
     */
    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> deleteFlower(
            @PathVariable @Min(1) Long id,
            HttpServletRequest request,
            Principal principal) {
        
        String ipAddress = getClientIpAddress(request);
        String username = principal.getName();
        
        try {
            // Get flower name before deletion for logging
            Optional<Flower> flower = flowerService.getFlowerById(id);
            if (!flower.isPresent()) {
                return ResponseEntity.notFound().build();
            }
            
            String flowerName = flower.get().getName();
            
            boolean deleted = flowerService.deleteFlower(id);
            
            if (deleted) {
                // Log successful deletion
                securityAuditService.logFlowerAction(username, "DELETE", flowerName, ipAddress, true, null);
                
                logger.info("Flower '{}' (ID: {}) deleted by admin '{}' from IP: {}", 
                           flowerName, id, username, ipAddress);
                
                return ResponseEntity.ok(Map.of(
                    "message", "Flower deleted successfully",
                    "deletedFlower", flowerName
                ));
            } else {
                return ResponseEntity.notFound().build();
            }
            
        } catch (Exception e) {
            logger.error("Error deleting flower {} by admin '{}': {}", id, username, e.getMessage());
            securityAuditService.logFlowerAction(username, "DELETE", "ID:" + id, ipAddress, false, e.getMessage());
            
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of(
                "error", "Failed to delete flower"
            ));
        }
    }

    /**
     * Get flowers by availability - accessible to authenticated users
     */
    @GetMapping("/availability/{status}")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<List<Flower>> getFlowersByAvailability(
            @PathVariable @NotBlank String status) {
        
        try {
            // Validate availability status
            if (!status.equals("Available") && !status.equals("Unavailable")) {
                return ResponseEntity.badRequest().build();
            }
            
            List<Flower> flowers = flowerService.getFlowersByAvailablity(status);
            return ResponseEntity.ok(flowers);
            
        } catch (Exception e) {
            logger.error("Error retrieving flowers by availability '{}': {}", status, e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * Extract client IP address from request headers
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
}