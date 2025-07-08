package com.example.Ecommerce.Controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/test")
public class testEndPoints {
    @GetMapping("/unsecure")
    public String unsecure() {
        return "Hello from un secure endpoint";
    }

    @GetMapping("/secure")
    public String secure() {
        return "Hello from  secure endpoint";
    }
}