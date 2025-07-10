package com.example.Ecommerce.ServiceImpl;

import com.cloudinary.Cloudinary;
import com.cloudinary.utils.ObjectUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class ImageService {

    private final Cloudinary cloudinary;

    public Map<String, String> uploadImage(MultipartFile file) throws IOException {
        Map uploadResult = cloudinary.uploader().upload(file.getBytes(), ObjectUtils.emptyMap());

        String imageUrl = uploadResult.get("secure_url").toString();
        String publicId = uploadResult.get("public_id").toString();

        Map<String, String> result = new HashMap<>();
        result.put("url", imageUrl);
        result.put("publicId", publicId);

        return result;
    }
    public boolean deleteImage(String profileImagePublicId) throws IOException {
        try{
            Map result=cloudinary.uploader().destroy(profileImagePublicId, ObjectUtils.emptyMap());
            return "ok".equals(result.get("status"));
        } catch (Exception e) {
            throw new IOException(e.getMessage());
        }
    }

}
