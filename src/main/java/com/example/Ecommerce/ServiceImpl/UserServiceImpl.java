package com.example.Ecommerce.ServiceImpl;

import com.example.Ecommerce.DTO.UpdateProfileRequest;
import com.example.Ecommerce.DTO.UserProfileResponse;
import com.example.Ecommerce.Exceptions.UserNotFoundException;
import com.example.Ecommerce.Mapper.UserMapper;
import com.example.Ecommerce.Model.User;
import com.example.Ecommerce.Repository.UserRepository;
import com.example.Ecommerce.Service.UserService;
import com.example.Ecommerce.config.JwtService;
import com.example.Ecommerce.token.TokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {


    private final UserRepository userRepository;
    private final ImageService imageService;
    private final UserMapper userMapper;
    private final JwtService jwtService;
    private final TokenService tokenService;

    @Override
    public UserProfileResponse updateUserProfile(UpdateProfileRequest request, MultipartFile imageFile) throws IOException {
        String currentEmail = ((UserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal()).getUsername();
   User user=userRepository.findByEmail(currentEmail) .orElseThrow(()->new UserNotFoundException("User Not Found"));
  if (imageFile!=null && !imageFile.isEmpty()) {
      if (user.getProfileImagePublicId()!=null) {
          imageService.deleteImage(user.getProfileImagePublicId());
      }
      Map<String,String> result=imageService.uploadImage(imageFile);
      user.setProfileImagePublicId(result.get("publicId"));
      user.setProfileImageUrl(result.get("url"));
  }
  boolean emailChanged=request.getEmail()!=null && !request.getEmail().equals(currentEmail);
  if (emailChanged && userRepository.findByEmail(currentEmail).isPresent()) {
      throw new IllegalArgumentException("Email Already Exists");
  }
  userMapper.updateUserFromDto(request,user);
  userRepository.save(user);

  if (emailChanged) {
      updateSecurityContext(user);
      String newToken= jwtService.generateToken(user);
      tokenService.revokeAllUserToken(user);
      tokenService.saveUserToken(user,newToken);

  }
  return userMapper.toUserProfileResponse(user);
    }
    private void updateSecurityContext(User user) {
        UsernamePasswordAuthenticationToken auth=new UsernamePasswordAuthenticationToken(user.getEmail(),null,user.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(auth);
    }
}
