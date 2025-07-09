package com.example.Ecommerce.Emails;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;


import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class EmailService {

    private final JavaMailSender mailSender;

    @Value("${spring.mail.username}")
    private String from;

    public void sendVerificationEmail(String email, String verificationToken) {
        String subject = "Verification Email";
        String path = "/api/v1/auth/verify";
        String message = "Click the link below to verify your email";
        sendEmail(email, verificationToken, subject, path, message);
    }

    public void sendForgetPasswordEmail(String email, String resetToken) {
        String subject = "Reset Your Password";
        String path = "/api/v1/auth/reset-password";
        String message = "Click the link below to reset your password";
        sendEmail(email, resetToken, subject, path, message);
    }

    private void sendEmail(String to, String token, String subject, String path, String bodyMessage) {
        try {
            MimeMessage mimeMessage = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true);

            helper.setFrom(from);
            helper.setTo(to);
            helper.setSubject(subject);

            // 👇 بناء لينك التوكن
            String link = "http://localhost:8080" + path + "?token=" + token;

            String htmlContent = "<p>" + bodyMessage + "</p>" +
                    "<a href=\"" + link + "\">Click here</a>";

            helper.setText(htmlContent, true);  // true = HTML

            mailSender.send(mimeMessage);
        } catch (MessagingException e) {
            throw new RuntimeException("Failed to send email", e);
        }
    }
}
