package com.example.Ecommerce.Controller;

import com.example.Ecommerce.DTO.ChangePasswordRequest;
import com.example.Ecommerce.Service.UserService;
import com.example.Ecommerce.auth.AuthenticationResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
@RequestMapping("/user")
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;

    @PostMapping("/change-password")
    public ResponseEntity<AuthenticationResponse> changePassword(@Valid @RequestBody ChangePasswordRequest request) {
        System.out.printf("iam in controller");
        AuthenticationResponse response = userService.changePassword(request);
        return ResponseEntity.ok(response);

    }
}
