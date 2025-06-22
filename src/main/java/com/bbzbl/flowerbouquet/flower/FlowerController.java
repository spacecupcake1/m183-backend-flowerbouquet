package com.bbzbl.flowerbouquet.flower;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
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

import com.bbzbl.flowerbouquet.security.EnhancedSecurityAuditService;
import com.bbzbl.flowerbouquet.validation.NoSqlInjection;
import com.bbzbl.flowerbouquet.validation.SecurityValidationService;
import com.bbzbl.flowerbouquet.validation.SecurityValidationService.InputType;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

@RestController
@RequestMapping("/api/flowers")
@Validated
public class FlowerController {

    @Autowired
    private FlowerService flowerService;

    @Autowired
    private EnhancedSecurityAuditService auditService;

    @Autowired
    private SecurityValidationService validationService;

    /**
     * Get all flowers - accessible to authenticated users
     */
    @GetMapping
    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    public ResponseEntity<List<Flower>> getAllFlowers(Authentication auth, HttpServletRequest request) {
        try {
            String username = auth.getName();
            String ipAddress = getClientIpAddress(request);
            
            // Log data access
            auditService.logDataAccessEvent(username, "Flower", "ALL", "READ", true, ipAddress);
            
            List<Flower> flowers = flowerService.getAllFlowers();
            return ResponseEntity.ok(flowers);
            
        } catch (Exception e) {
            auditService.logDataAccessEvent(auth.getName(), "Flower", "ALL", "READ", false, 
                                          getClientIpAddress(request));
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * Get flower by ID - accessible to authenticated users
     */
    @GetMapping("/{id}")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    public ResponseEntity<Flower> getFlowerById(@PathVariable Long id, 
                                               Authentication auth, HttpServletRequest request) {
        try {
            String username = auth.getName();
            String ipAddress = getClientIpAddress(request);
            
            Optional<Flower> flower = flowerService.getFlowerById(id);
            
            if (flower.isPresent()) {
                auditService.logDataAccessEvent(username, "Flower", id.toString(), "READ", true, ipAddress);
                return ResponseEntity.ok(flower.get());
            } else {
                auditService.logDataAccessEvent(username, "Flower", id.toString(), "READ", false, ipAddress);
                return ResponseEntity.notFound().build();
            }
            
        } catch (Exception e) {
            auditService.logDataAccessEvent(auth.getName(), "Flower", id.toString(), "READ", false, 
                                          getClientIpAddress(request));
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * Search flowers with input validation - FIXED METHOD NAME
     */
    @GetMapping("/search")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    public ResponseEntity<List<Flower>> searchFlowers(
            @RequestParam @NotBlank @Size(max = 100) @NoSqlInjection String searchTerm,
            Authentication auth, HttpServletRequest request) {
        
        try {
            String username = auth.getName();
            String ipAddress = getClientIpAddress(request);
            
            // Validate and sanitize search input
            SecurityValidationService.ValidationResult validation = 
                validationService.validateInput(searchTerm, "searchTerm", InputType.SEARCH_TERM);
            
            if (!validation.isValid()) {
                auditService.logSecurityViolation(username, "INVALID_SEARCH_INPUT", 
                    "Search term: " + searchTerm + ", Errors: " + validation.getErrors(), 
                    ipAddress, request);
                return ResponseEntity.badRequest().build();
            }

            String sanitizedSearchTerm = validation.getSanitized();
            
            // Log search activity
            auditService.logDataAccessEvent(username, "Flower", "SEARCH:" + sanitizedSearchTerm, 
                                          "READ", true, ipAddress);
            
            // Use the correct FlowerService method
            List<Flower> flowers = flowerService.searchFlowersByName(sanitizedSearchTerm);
            return ResponseEntity.ok(flowers);
            
        } catch (Exception e) {
            auditService.logDataAccessEvent(auth.getName(), "Flower", "SEARCH", "READ", false, 
                                          getClientIpAddress(request));
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * Get flowers by availability
     */
    @GetMapping("/availability/{status}")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    public ResponseEntity<List<Flower>> getFlowersByAvailability(@PathVariable String status,
                                                                Authentication auth, HttpServletRequest request) {
        try {
            String username = auth.getName();
            String ipAddress = getClientIpAddress(request);
            
            // Validate availability status
            if (!status.equals("Available") && !status.equals("Unavailable")) {
                return ResponseEntity.badRequest().build();
            }
            
            List<Flower> flowers = flowerService.getFlowersByAvailablity(status);
            
            auditService.logDataAccessEvent(username, "Flower", "AVAILABILITY:" + status, 
                                          "READ", true, ipAddress);
            
            return ResponseEntity.ok(flowers);
            
        } catch (Exception e) {
            auditService.logDataAccessEvent(auth.getName(), "Flower", "AVAILABILITY", "READ", false, 
                                          getClientIpAddress(request));
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * Create flower - Admin only - FIXED TO USE FLOWER ENTITY
     */
    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Flower> createFlower(@Valid @RequestBody FlowerDTO flowerDTO,
                                              Authentication auth, HttpServletRequest request) {
        try {
            String username = auth.getName();
            String ipAddress = getClientIpAddress(request);
            
            // Additional server-side validation
            if (!validateFlowerDTO(flowerDTO, username, ipAddress, request)) {
                return ResponseEntity.badRequest().build();
            }
            
            // Convert DTO to Entity
            Flower flower = convertDtoToEntity(flowerDTO);
            
            // Use the correct FlowerService method that expects Flower entity
            Flower createdFlower = flowerService.createFlower(flower);
            
            auditService.logDataAccessEvent(username, "Flower", createdFlower.getId().toString(), 
                                          "CREATE", true, ipAddress);
            
            return ResponseEntity.status(HttpStatus.CREATED).body(createdFlower);
            
        } catch (Exception e) {
            auditService.logDataAccessEvent(auth.getName(), "Flower", "NEW", "CREATE", false, 
                                          getClientIpAddress(request));
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * Update flower - Admin only - FIXED TO USE FLOWER ENTITY
     */
    @PutMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Flower> updateFlower(@PathVariable Long id, 
                                              @Valid @RequestBody FlowerDTO flowerDTO,
                                              Authentication auth, HttpServletRequest request) {
        try {
            String username = auth.getName();
            String ipAddress = getClientIpAddress(request);
            
            // Additional server-side validation
            if (!validateFlowerDTO(flowerDTO, username, ipAddress, request)) {
                return ResponseEntity.badRequest().build();
            }
            
            // Convert DTO to Entity
            Flower flowerUpdate = convertDtoToEntity(flowerDTO);
            
            // Use the correct FlowerService method that expects Flower entity and returns Optional
            Optional<Flower> updatedFlowerOpt = flowerService.updateFlower(id, flowerUpdate);
            
            if (updatedFlowerOpt.isPresent()) {
                Flower updatedFlower = updatedFlowerOpt.get();
                auditService.logDataAccessEvent(username, "Flower", id.toString(), 
                                              "UPDATE", true, ipAddress);
                return ResponseEntity.ok(updatedFlower);
            } else {
                auditService.logDataAccessEvent(username, "Flower", id.toString(), 
                                              "UPDATE", false, ipAddress);
                return ResponseEntity.notFound().build();
            }
            
        } catch (Exception e) {
            auditService.logDataAccessEvent(auth.getName(), "Flower", id.toString(), 
                                          "UPDATE", false, getClientIpAddress(request));
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * Delete flower - Admin only
     */
    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> deleteFlower(@PathVariable Long id,
                                            Authentication auth, HttpServletRequest request) {
        try {
            String username = auth.getName();
            String ipAddress = getClientIpAddress(request);
            
            boolean deleted = flowerService.deleteFlower(id);
            
            if (deleted) {
                auditService.logDataAccessEvent(username, "Flower", id.toString(), 
                                              "DELETE", true, ipAddress);
                return ResponseEntity.noContent().build();
            } else {
                auditService.logDataAccessEvent(username, "Flower", id.toString(), 
                                              "DELETE", false, ipAddress);
                return ResponseEntity.notFound().build();
            }
            
        } catch (Exception e) {
            auditService.logDataAccessEvent(auth.getName(), "Flower", id.toString(), 
                                          "DELETE", false, getClientIpAddress(request));
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    // ========== HELPER METHODS ==========

    /**
     * Convert FlowerDTO to Flower entity
     */
    private Flower convertDtoToEntity(FlowerDTO flowerDTO) {
    Flower flower = new Flower();
    flower.setName(flowerDTO.getName());
    flower.setMeaning(flowerDTO.getMeaning());
    flower.setAvailablity(flowerDTO.getAvailability());
    // flower.setAvailability(flowerDTO.getAvailability());
    flower.setInfo(flowerDTO.getInfo());
    flower.setColor(flowerDTO.getColor());
    flower.setPrice(flowerDTO.getPrice().intValue()); // Convert BigDecimal to int if needed
    flower.setImageUrl(flowerDTO.getImageUrl());
    return flower;
}

    /**
     * Additional server-side validation for flower DTOs
     */
    private boolean validateFlowerDTO(FlowerDTO flowerDTO, String username, String ipAddress, 
                                    HttpServletRequest request) {
        
        // Validate name
        SecurityValidationService.ValidationResult nameValidation = 
            validationService.validateInput(flowerDTO.getName(), "name", InputType.FLOWER_NAME);
        if (!nameValidation.isValid()) {
            auditService.logSecurityViolation(username, "INVALID_FLOWER_NAME", 
                nameValidation.getFirstError(), ipAddress, request);
            return false;
        }

        // Validate description fields
        if (flowerDTO.getMeaning() != null) {
            SecurityValidationService.ValidationResult meaningValidation = 
                validationService.validateInput(flowerDTO.getMeaning(), "meaning", InputType.DESCRIPTION);
            if (!meaningValidation.isValid()) {
                auditService.logSecurityViolation(username, "INVALID_FLOWER_MEANING", 
                    meaningValidation.getFirstError(), ipAddress, request);
                return false;
            }
        }

        // Validate info field
        if (flowerDTO.getInfo() != null) {
            SecurityValidationService.ValidationResult infoValidation = 
                validationService.validateInput(flowerDTO.getInfo(), "info", InputType.DESCRIPTION);
            if (!infoValidation.isValid()) {
                auditService.logSecurityViolation(username, "INVALID_FLOWER_INFO", 
                    infoValidation.getFirstError(), ipAddress, request);
                return false;
            }
        }

        // Validate color
        if (flowerDTO.getColor() != null) {
            SecurityValidationService.ValidationResult colorValidation = 
                validationService.validateInput(flowerDTO.getColor(), "color", InputType.GENERIC);
            if (!colorValidation.isValid()) {
                auditService.logSecurityViolation(username, "INVALID_FLOWER_COLOR", 
                    colorValidation.getFirstError(), ipAddress, request);
                return false;
            }
        }

        // Validate URL if provided
        if (flowerDTO.getImageUrl() != null && !flowerDTO.getImageUrl().isEmpty()) {
            SecurityValidationService.ValidationResult urlValidation = 
                validationService.validateInput(flowerDTO.getImageUrl(), "imageUrl", InputType.URL);
            if (!urlValidation.isValid()) {
                auditService.logSecurityViolation(username, "INVALID_IMAGE_URL", 
                    urlValidation.getFirstError(), ipAddress, request);
                return false;
            }
        }

        return true;
    }

    /**
     * Get client IP address from request
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