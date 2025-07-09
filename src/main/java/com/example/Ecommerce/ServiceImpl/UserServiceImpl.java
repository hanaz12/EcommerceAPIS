package com.example.Ecommerce.ServiceImpl;

import com.example.Ecommerce.auth.DTOs.ChangePasswordRequest;
import com.example.Ecommerce.Exceptions.UserNotFoundException;
import com.example.Ecommerce.Repository.UserRepository;
import com.example.Ecommerce.Service.UserService;
import com.example.Ecommerce.auth.DTOs.AuthenticationResponse;
import com.example.Ecommerce.auth.AuthenticationService;
import com.example.Ecommerce.config.JwtService;
import com.example.Ecommerce.token.TokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {



}
