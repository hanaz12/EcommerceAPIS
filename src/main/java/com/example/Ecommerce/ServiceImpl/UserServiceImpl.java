package com.example.Ecommerce.ServiceImpl;

import com.example.Ecommerce.DTO.ChangePasswordRequest;
import com.example.Ecommerce.Exceptions.UserNotFoundException;
import com.example.Ecommerce.Repository.UserRepository;
import com.example.Ecommerce.Service.UserService;
import com.example.Ecommerce.auth.AuthenticationResponse;
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

private final UserRepository userRepository;
private final PasswordEncoder passwordEncoder;
private final AuthenticationService authenticationService;
private final TokenService tokenService;
private final JwtService jwtService;
    @Override
    public AuthenticationResponse changePassword(ChangePasswordRequest request) {
        String email = ((UserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal()).getUsername();
        var user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        if (!passwordEncoder.matches(request.getOldPassword(), user.getPassword())) {
            throw new IllegalArgumentException("Old password is incorrect.");
        }

        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);

        tokenService.revokeAllUserToken(user);
        String accessToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);
        tokenService.saveUserToken(user, accessToken);

        return AuthenticationResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }
}
