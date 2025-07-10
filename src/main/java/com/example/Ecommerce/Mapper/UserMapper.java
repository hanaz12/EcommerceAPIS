package com.example.Ecommerce.Mapper;

import com.example.Ecommerce.DTO.UpdateProfileRequest;
import com.example.Ecommerce.DTO.UserProfileResponse;
import com.example.Ecommerce.Model.User;
import org.mapstruct.BeanMapping;
import org.mapstruct.Mapper;
import org.mapstruct.MappingTarget;
import org.mapstruct.NullValuePropertyMappingStrategy;

@Mapper(componentModel = "spring")
public interface UserMapper {

    @BeanMapping(nullValuePropertyMappingStrategy = NullValuePropertyMappingStrategy.IGNORE)
    void updateUserFromDto(UpdateProfileRequest request, @MappingTarget User user);

    UserProfileResponse toUserProfileResponse(User user);
}