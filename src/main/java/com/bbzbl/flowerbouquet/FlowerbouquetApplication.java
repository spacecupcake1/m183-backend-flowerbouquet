package com.bbzbl.flowerbouquet;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class FlowerbouquetApplication {

	public static void main(String[] args) {
		SpringApplication.run(FlowerbouquetApplication.class, args);
	}

}
