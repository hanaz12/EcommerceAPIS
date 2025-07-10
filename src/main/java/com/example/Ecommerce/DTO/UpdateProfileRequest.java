package com.example.Ecommerce.DTO;


import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UpdateProfileRequest {
    private String fullName;
    @Email(message = "Email should be valid")
    private String email;

    @Pattern(regexp = "01[0125][0-9]{8}", message = "Phone must be valid")
    private String phone;
}
