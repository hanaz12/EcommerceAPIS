package com.example.Ecommerce.auth;

import com.example.Ecommerce.Exceptions.UserNotFoundException;
import com.example.Ecommerce.Enums.Role;
import com.example.Ecommerce.Model.User;
import com.example.Ecommerce.Repository.UserRepository;
import com.example.Ecommerce.auth.DTOs.*;
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

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        System.out.println("in auth method");
        var user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new UserNotFoundException("Invalid email or password"));
        System.out.println("user found");

        if (!user.getIsEnabled() || !user.getIsEmailVerified()) {
            System.out.println("user not enabled");
            throw new IllegalArgumentException("Account is not verified. Please check your email.");
        }

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
    public ResponseEntity<AuthenticationResponse> verifyAccount(String token) {
        var user = userRepository.findByVerificationToken(token)
                .orElseThrow(() -> new IllegalArgumentException("Invalid verification token"));

        if (user.getVerificationTokenExpiry().isBefore(LocalDateTime.now())) {
            throw new IllegalArgumentException("Verification token expired please request a new one");
        }

        user.setIsEnabled(true);
        user.setIsEmailVerified(true);
        user.setVerificationToken(null);
        user.setVerificationTokenExpiry(null);
        userRepository.save(user);

        return ResponseEntity.ok(
                AuthenticationResponse.builder()
                        .accessToken(jwtService.generateToken(user))
                        .refreshToken(jwtService.generateRefreshToken(user))
                        .build()
        );

    }

    public void resendVerificationEmail(String email) {
        var user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        if (user.getIsEmailVerified()) {
            throw new IllegalStateException("Email is already verified.");
        }

        String newToken = UUID.randomUUID().toString();
        user.setVerificationToken(newToken);
        user.setVerificationTokenExpiry(LocalDateTime.now().plusMinutes(15));
        userRepository.save(user);

        emailService.sendVerificationEmail(user.getEmail(), newToken);
    }
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
    public ResponseEntity<String> resetPassword(ResetPasswordRequest request) {
        var user = userRepository.findByResetToken(request.getToken())
                .orElseThrow(() -> new IllegalArgumentException("Invalid reset token"));

        if (user.getResetTokenExpiry().isBefore(LocalDateTime.now())) {
            throw new IllegalArgumentException("Reset token has expired.");
        }

        // password strength check (اختياري)
        Zxcvbn passwordChecker = new Zxcvbn();
        Strength strength = passwordChecker.measure(request.getNewPassword());
        if (strength.getScore() < 3) {
            throw new IllegalArgumentException("Password is too weak.");
        }

        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        user.setResetToken(null);
        user.setResetTokenExpiry(null);
        userRepository.save(user);

        return ResponseEntity.ok("Password has been reset successfully.");
    }


    public ResponseEntity<String> resetPasswordMailSender(String email) {
        var user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UserNotFoundException("User not found"));
        String newToken = UUID.randomUUID().toString();
        user.setResetToken(newToken);
        user.setResetTokenExpiry(LocalDateTime.now().plusMinutes(15));
        userRepository.save(user);
        emailService.sendForgetPasswordEmail(user.getEmail(), newToken);
        return ResponseEntity.ok("Reset password mail sent.");

    }
}
