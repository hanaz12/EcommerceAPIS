package com.example.Ecommerce.Service;

import com.example.Ecommerce.DTO.ChangePasswordRequest;
import com.example.Ecommerce.auth.AuthenticationRequest;
import com.example.Ecommerce.auth.AuthenticationResponse;
public interface UserService {
    public AuthenticationResponse changePassword(ChangePasswordRequest changePasswordRequest);
}
