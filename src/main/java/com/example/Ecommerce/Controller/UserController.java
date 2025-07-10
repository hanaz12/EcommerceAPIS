package com.example.Ecommerce.Controller;

import com.example.Ecommerce.DTO.UpdateProfileRequest;
import com.example.Ecommerce.DTO.UserProfileResponse;
import com.example.Ecommerce.auth.DTOs.ChangePasswordRequest;
import com.example.Ecommerce.Service.UserService;
import com.example.Ecommerce.auth.DTOs.AuthenticationResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;


@RestController
@RequestMapping("/user")

@RequiredArgsConstructor
public class UserController {
private final UserService userService;


    @PatchMapping(value = "/profile", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<UserProfileResponse> updateProfile(
            @RequestPart("user") String userJson,
            @RequestPart(value = "image", required = false) MultipartFile profileImage
    ) throws IOException {
        ObjectMapper objectMapper = new ObjectMapper();
        UpdateProfileRequest updateProfileRequest = objectMapper.readValue(userJson, UpdateProfileRequest.class);
        UserProfileResponse response = userService.updateUserProfile(updateProfileRequest, profileImage);
        return ResponseEntity.ok(response);
    }

}
