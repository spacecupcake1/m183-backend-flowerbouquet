package com.bbzbl.flowerbouquet.flower;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST controller for managing flowers.
 */
@RestController
@RequestMapping("/api/flowers")
public class FlowerController {

    private final FlowerService flowerService;
    private final FlowerTempService flowerTempService;

    /**
     * Constructor for FlowerController.
     *
     * @param flowerService the flower service to handle flower-related operations
     * @param flowerTempService the temporary flower service to handle temporary flower storage operations
     */
    @Autowired
    public FlowerController(FlowerService flowerService, FlowerTempService flowerTempService) {
        this.flowerService = flowerService;
        this.flowerTempService = flowerTempService;
    }

    /**
     * GET /api/flowers : Get all flowers.
     *
     * @return a list of all flowers
     */
    @GetMapping
    public List<Flower> getAllFlowers() {
        return flowerService.getAllFlowers();
    }

    /**
     * GET /api/flowers/{id} : Get a flower by its ID.
     *
     * @param id the ID of the flower to retrieve
     * @return the ResponseEntity with status 200 (OK) and with body the flower, or with status 404 (Not Found) if the flower is not found
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

    /**
     * POST /api/flowers/customize : Add a flower to temporary storage.
     *
     * @param flower the flower to add
     * @return a response entity indicating success
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
     *
     * @return a response entity with the list of temporary flowers
     */
    @GetMapping("/customize")
    public ResponseEntity<List<Flower>> getTempFlowers() {
        return ResponseEntity.ok(flowerTempService.getTempFlowers());
    }

    /**
     * GET /api/flowers/customize/total-price : Calculate the total price of all flowers in temporary storage, including delivery if enabled.
     *
     * @return a response entity with the total price
     */
    @GetMapping("/customize/total-price")
    public ResponseEntity<Integer> getTotalPrice() {
        int totalPrice = flowerTempService.calculateTotalPrice();
        return ResponseEntity.ok(totalPrice);
    }

    /**
     * GET /api/flowers/customize/clear : Clear all flowers from temporary storage.
     *
     * @return a response entity indicating that the temporary storage has been cleared
     */
    @GetMapping("/customize/clear")
    public ResponseEntity<String> clearTempFlowers() {
        flowerTempService.clearTempFlowers();
        return ResponseEntity.ok("Temporary flower storage cleared");
    }

    /**
     * POST /api/flowers/customize/delivery : Enable or disable the delivery charge.
     *
     * @param enable boolean indicating if delivery is enabled
     * @return a response entity indicating the state of the delivery option
     */
    @PostMapping("/customize/delivery")
    public ResponseEntity<String> setDeliveryOption(@RequestBody boolean enable) {
        flowerTempService.setDeliveryEnabled(enable);
        return ResponseEntity.ok("Delivery option has been " + (enable ? "enabled" : "disabled"));
    }
}
