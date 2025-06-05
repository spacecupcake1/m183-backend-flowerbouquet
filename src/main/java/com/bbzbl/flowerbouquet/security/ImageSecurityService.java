package com.bbzbl.flowerbouquet.security;

import java.net.URL;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

import org.springframework.stereotype.Service;

@Service
public class ImageSecurityService {
    
    private static final List<String> ALLOWED_EXTENSIONS = Arrays.asList(
        ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg"
    );
    
    private static final List<String> ALLOWED_DOMAINS = Arrays.asList(
        "localhost",
        "127.0.0.1",
        "yourdomain.com",
        "cdn.yourdomain.com"
        // Add your trusted domains here
    );
    
    private static final Pattern RELATIVE_PATH_PATTERN = Pattern.compile(
        "^images/[a-zA-Z0-9._-]+\\.(jpg|jpeg|png|gif|webp|svg)$"
    );
    
    /**
     * Validates if an image URL is safe for storage and display
     */
    public boolean isSafeImageUrl(String imageUrl) {
        if (imageUrl == null || imageUrl.trim().isEmpty()) {
            return false;
        }
        
        imageUrl = imageUrl.trim();
        
        // Check for relative paths (preferred for security)
        if (isValidRelativePath(imageUrl)) {
            return true;
        }
        
        // Check for absolute URLs
        if (isValidAbsoluteUrl(imageUrl)) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Validates relative paths for images
     */
    private boolean isValidRelativePath(String path) {
        // Must start with images/ for flat structure
        if (!path.startsWith("images/")) {
            return false;
        }
        
        // Must match the allowed pattern (flat structure)
        if (!RELATIVE_PATH_PATTERN.matcher(path).matches()) {
            return false;
        }
        
        // Check for path traversal attempts
        if (path.contains("..") || path.contains("//")) {
            return false;
        }
        
        return hasAllowedExtension(path);
    }
    
    /**
     * Validates absolute URLs for images
     */
    private boolean isValidAbsoluteUrl(String url) {
        try {
            URL parsedUrl = new URL(url);
            
            // Must be HTTP or HTTPS
            if (!"http".equals(parsedUrl.getProtocol()) && !"https".equals(parsedUrl.getProtocol())) {
                return false;
            }
            
            // Check if domain is allowed
            String host = parsedUrl.getHost();
            if (host == null || !ALLOWED_DOMAINS.contains(host)) {
                return false;
            }
            
            // Check file extension
            return hasAllowedExtension(url);
            
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Checks if the URL has an allowed file extension
     */
    private boolean hasAllowedExtension(String url) {
        String lowerUrl = url.toLowerCase();
        return ALLOWED_EXTENSIONS.stream().anyMatch(lowerUrl::endsWith);
    }
    
    /**
     * Sanitizes an image URL by removing potentially dangerous characters
     */
    public String sanitizeImageUrl(String imageUrl) {
        if (imageUrl == null) {
            return null;
        }
        
        // Remove any potentially dangerous characters
        String sanitized = imageUrl.trim()
            .replaceAll("[<>\"'&]", "") // Remove HTML/XML special characters
            .replaceAll("\\s+", "%20"); // Replace spaces with URL encoding
        
        return sanitized;
    }
    
    /**
     * Normalizes relative paths to ensure consistency (flat structure)
     */
    public String normalizeImagePath(String path) {
        if (path == null) {
            return null;
        }
        
        path = path.trim();
        
        // Remove leading slash if present
        if (path.startsWith("/")) {
            path = path.substring(1);
        }
        
        // Ensure it starts with images/ for flat structure
        if (!path.startsWith("images/")) {
            path = "images/" + path;
        }
        
        return path;
    }
}