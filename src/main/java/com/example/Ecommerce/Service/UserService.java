package com.example.Ecommerce.Service;

import com.example.Ecommerce.DTO.UpdateProfileRequest;
import com.example.Ecommerce.DTO.UserProfileResponse;
import com.example.Ecommerce.auth.DTOs.ChangePasswordRequest;
import com.example.Ecommerce.auth.DTOs.AuthenticationResponse;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

public interface UserService {
    UserProfileResponse updateUserProfile(UpdateProfileRequest request, MultipartFile imageFile) throws IOException;
}
