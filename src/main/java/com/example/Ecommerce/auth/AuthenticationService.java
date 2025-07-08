package com.example.Ecommerce.auth;

import com.example.Ecommerce.DTO.ChangePasswordRequest;
import com.example.Ecommerce.Exceptions.UserNotFoundException;
import com.example.Ecommerce.Enums.Role;
import com.example.Ecommerce.Model.User;
import com.example.Ecommerce.Repository.UserRepository;
import com.example.Ecommerce.config.JwtService;
import com.nulabinc.zxcvbn.Strength;
import com.nulabinc.zxcvbn.Zxcvbn;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import com.example.Ecommerce.token.TokenService;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;
    private final TokenService tokenService;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    // ✅ تسجيل مستخدم عادي
    public AuthenticationResponse register(RegisterRequest request) {
        return registerWithRole(request, Role.USER);
    }


    public AuthenticationResponse registerAdmin(RegisterRequest request) {
        return registerWithRole(request, Role.ADMIN);
    }

    // ✅ ميثود موحدة للتسجيل بأي Role
    private AuthenticationResponse registerWithRole(RegisterRequest request, Role role) {
        Zxcvbn passwordChecker = new Zxcvbn();
        Strength strength = passwordChecker.measure(request.getPassword());

        if (strength.getScore() < 3) {
            throw new IllegalArgumentException("Password is too weak. Try using symbols, uppercase letters, and longer length.");
        }

        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new IllegalArgumentException("Email already exists.");
        }

        var user = User.builder()
                .fullName(request.getFullName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .phone(request.getPhone())
                .profileImageUrl(request.getProfileImageUrl())
                .role(role)
                .isEnabled(true)
                .isEmailVerified(false)
                .build();

        var savedUser = userRepository.save(user);
        var jwtToken = jwtService.generateToken(savedUser);
        var refreshToken = jwtService.generateRefreshToken(savedUser);
        tokenService. saveUserToken(savedUser, jwtToken);

        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .build();
    }

    // ✅ تسجيل الدخول
    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getEmail(),
                            request.getPassword()
                    )
            );
        } catch (Exception e) {
            throw new UserNotFoundException("Invalid email or password");
        }

        var user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new UserNotFoundException("Invalid email or password"));

        var jwtToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);

        tokenService.revokeAllUserToken(user);
        tokenService.saveUserToken(user, jwtToken);

        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .build();
    }





}
