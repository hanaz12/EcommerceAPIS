package com.example.Ecommerce.Exceptions;

import lombok.Data;

import java.util.HashMap;
import java.util.Map;

@Data
public  class ErrorResponse {
    private String errorCode;
    private String message;
    private int status;
    private Map<String, String> details;

    public ErrorResponse(String errorCode, String message, int status) {
        this.errorCode = errorCode;
        this.message = message;
        this.status = status;
        this.details = new HashMap<>();
    }
}
