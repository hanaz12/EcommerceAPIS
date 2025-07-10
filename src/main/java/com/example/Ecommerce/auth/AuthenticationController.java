package com.example.Ecommerce.auth;


import com.example.Ecommerce.Emails.EmailService;
import com.example.Ecommerce.auth.DTOs.*;
import com.example.Ecommerce.token.TokenService;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {
    private final AuthenticationService authenticationService;
    private final TokenService tokenService;
    private final ObjectMapper objectMapper;

    @PostMapping(value = "/register", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<AuthenticationResponse> register(
            @RequestPart("user") String userJson,
            @RequestPart(value = "image", required = false) MultipartFile image
    ) throws IOException {
        System.out.println("Receiving multipart request");

        RegisterRequest request = objectMapper.readValue(userJson, RegisterRequest.class);
        return ResponseEntity.ok(authenticationService.register(request, image));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> authenticate(
            @RequestBody AuthenticationRequest request
    ) {
        return ResponseEntity.ok(authenticationService.authenticate(request));

    }

    @PostMapping("/refresh-token")
    public void refreshToken(
            HttpServletRequest request,
            HttpServletResponse response
    ) throws IOException {
        tokenService.refreshToken(request, response);
    }
    @GetMapping("/verify")
    public ResponseEntity<AuthenticationResponse> verifyEmail(@RequestParam("token") String token) {
        return authenticationService.verifyAccount(token);
    }
    @PostMapping("/resend-verification")
    public ResponseEntity<String> resendVerification(@RequestParam String email) {
        authenticationService.resendVerificationEmail(email);
        return ResponseEntity.ok("Verification email resent to " + email);
    }
    @PostMapping("/change-password")
    public ResponseEntity<AuthenticationResponse> changePassword(@Valid @RequestBody ChangePasswordRequest request) {
        System.out.printf("iam in controller");
        AuthenticationResponse response = authenticationService.changePassword(request);
        return ResponseEntity.ok(response);

    }
    @PostMapping("/forgot-password")
    public ResponseEntity<String> sendResetPasswordMail(@RequestParam String email) {
        return authenticationService.resetPasswordMailSender(email);
    }

    @PostMapping("/reset-password")
    public ResponseEntity<String> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        return authenticationService.resetPassword(request);
    }



}
