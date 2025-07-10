package com.example.Ecommerce.DTO;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class UserProfileResponse {
    private String fullName;
    private String email;
    private String phone;
    private String profileImageUrl;
}

