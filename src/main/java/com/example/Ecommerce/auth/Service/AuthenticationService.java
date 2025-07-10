package com.example.Ecommerce.auth.Service;

import com.example.Ecommerce.Exceptions.UserNotFoundException;
import com.example.Ecommerce.Enums.Role;
import com.example.Ecommerce.Model.User;
import com.example.Ecommerce.Repository.UserRepository;
import com.example.Ecommerce.ServiceImpl.ImageService;
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
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Map;
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
 private final ImageService imageService;
 private final PasswordValidatorService passwordValidatorService;

 private Map<String , String> uploadImageIfPresent(MultipartFile file) throws IOException {
     if(file!=null && !file.isEmpty()){
         return imageService.uploadImage(file);
     }
     return Map.of("url" , null , "publicId" , null);
 }
 private User buildUser(RegisterRequest registerRequest, Role role , String imgUrl , String publicId,String token , LocalDateTime expiry ) {
     return User.builder()
             .fullName(registerRequest.getFullName())
             .email(registerRequest.getEmail())
             .password(passwordEncoder.encode(registerRequest.getPassword()))
             .phone(registerRequest.getPhone())
             .profileImageUrl(imgUrl)
             .profileImagePublicId(publicId)
             .isEnabled(false)
             .isEmailVerified(false)
             .verificationToken(token)
             .verificationTokenExpiry(expiry)
             .role(role)
             .build();
 }

    // ✅ تسجيل مستخدم عادي
    public AuthenticationResponse register(RegisterRequest request , MultipartFile image) throws IOException {
        System.out.println("in a register method user");
        return registerWithRole(request, Role.USER,image);
    }

    // ✅ تسجيل أدمن
    public AuthenticationResponse registerAdmin(RegisterRequest request ,  MultipartFile image) throws IOException {
        return registerWithRole(request, Role.ADMIN , image);
    }

    // ✅ ميثود موحدة للتسجيل بأي Role
    private AuthenticationResponse registerWithRole(RegisterRequest request, Role role, MultipartFile imageFile) throws IOException {

        passwordValidatorService.validate(request.getPassword());
        // 2. Check if email already exists
        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new IllegalArgumentException("Email already exists.");
        }

       Map<String,String> uploadImageResult = uploadImageIfPresent(imageFile);
        String imgUrl= uploadImageResult.get("url");
        String publicId = uploadImageResult.get("publicId");

        // 4. Generate verification token
        String verificationToken = UUID.randomUUID().toString();
        LocalDateTime expiry = LocalDateTime.now().plusHours(24);

        User user=buildUser(request,role,imgUrl,publicId,verificationToken,expiry);
        var savedUser = userRepository.save(user);
        emailService.sendVerificationEmail(user.getEmail(), verificationToken);

        return AuthenticationResponse.builder()
                .accessToken("Account created. Please verify your email.")
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
        passwordValidatorService.validate(request.getNewPassword());

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

        passwordValidatorService.validate(request.getNewPassword());

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
