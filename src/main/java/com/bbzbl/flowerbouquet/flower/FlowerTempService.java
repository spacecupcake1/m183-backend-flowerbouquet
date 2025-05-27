package com.bbzbl.flowerbouquet.flower;

import org.springframework.stereotype.Service;
import java.util.ArrayList;
import java.util.List;

@Service
public class FlowerTempService {
    private List<Flower> tempFlowerStore = new ArrayList<>();
    private boolean deliveryEnabled = false;

    public void addFlowerToTemp(Flower flower) {
        tempFlowerStore.add(flower);
    }

    public List<Flower> getTempFlowers() {
        return tempFlowerStore;
    }

    public void clearTempFlowers() {
        tempFlowerStore.clear();
    }

    public int calculateTotalPrice() {
        int totalPrice = tempFlowerStore.stream()
                              .mapToInt(Flower::getPrice)
                              .sum();
        return deliveryEnabled ? totalPrice + 10 : totalPrice;
    }

    public void setDeliveryEnabled(boolean enabled) {
        deliveryEnabled = enabled;
    }
}
