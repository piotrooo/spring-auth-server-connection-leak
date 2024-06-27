package com.example.connectionleak;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class ConnectionleakApplication {

    public static void main(String[] args) {
        SpringApplication.run(ConnectionleakApplication.class, args);
    }

}
