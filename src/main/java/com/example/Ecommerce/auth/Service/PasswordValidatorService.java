package com.example.Ecommerce.auth.Service;

import com.nulabinc.zxcvbn.Strength;
import com.nulabinc.zxcvbn.Zxcvbn;
import org.springframework.stereotype.Service;

@Service
public class PasswordValidatorService {
    public void validate(String password) {
        Zxcvbn zxcvbn=new Zxcvbn();
        Strength strength=zxcvbn.measure(password);
        if (strength.getScore()<3){
            throw new IllegalArgumentException("Password is too weak.");
        }
    }
}
