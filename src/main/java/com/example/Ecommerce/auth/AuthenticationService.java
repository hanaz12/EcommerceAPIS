package com.example.Ecommerce.auth;

import com.example.Ecommerce.DTO.ChangePasswordRequest;
import com.example.Ecommerce.Exceptions.UserNotFoundException;
import com.example.Ecommerce.Enums.Role;
import com.example.Ecommerce.Model.User;
import com.example.Ecommerce.Repository.UserRepository;
import com.example.Ecommerce.config.JwtService;
import com.example.Ecommerce.token.TokenService;
import com.example.Ecommerce.Emails.EmailService;
import com.nulabinc.zxcvbn.Strength;
import com.nulabinc.zxcvbn.Zxcvbn;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;
    private final TokenService tokenService;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final EmailService emailService;

    // ✅ تسجيل مستخدم عادي
    public AuthenticationResponse register(RegisterRequest request) {
        return registerWithRole(request, Role.USER);
    }

    // ✅ تسجيل أدمن
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

        String verificationToken = UUID.randomUUID().toString();
        LocalDateTime expiry = LocalDateTime.now().plusHours(24);

        var user = User.builder()
                .fullName(request.getFullName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .phone(request.getPhone())
                .profileImageUrl(request.getProfileImageUrl())
                .role(role)
                .isEnabled(false) // الحساب لسه مش مفعل
                .isEmailVerified(false)
                .verificationToken(verificationToken)
                .verificationTokenExpiry(expiry)
                .build();

        var savedUser = userRepository.save(user);
        emailService.sendVerificationEmail(user.getEmail(), verificationToken);

        return AuthenticationResponse.builder()
                .accessToken("Account created. Please verify your email.")
                .refreshToken(null)
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

        if (!user.getIsEnabled()) {
            throw new IllegalStateException("Account is not verified. Please check your email.");
        }

        var jwtToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);

        tokenService.revokeAllUserToken(user);
        tokenService.saveUserToken(user, jwtToken);

        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .build();
    }

    // ✅ تفعيل الحساب عن طريق التوكن
    public ResponseEntity<String> verifyAccount(String token) {
        var user = userRepository.findByVerificationToken(token)
                .orElseThrow(() -> new IllegalArgumentException("Invalid verification token"));

        if (user.getVerificationTokenExpiry().isBefore(LocalDateTime.now())) {
            throw new IllegalArgumentException("Verification token expired");
        }

        user.setIsEnabled(true);
        user.setIsEmailVerified(true);
        user.setVerificationToken(null);
        user.setVerificationTokenExpiry(null);
        userRepository.save(user);

        return ResponseEntity.ok("Account verified successfully");
    }
}
