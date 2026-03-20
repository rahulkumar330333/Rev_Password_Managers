package com.passmanager.controller;

import com.passmanager.entity.SecurityQuestion;
import com.passmanager.entity.User;
import com.passmanager.service.EmailService;
import com.passmanager.service.UserService;
import jakarta.servlet.http.HttpSession;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.List;
import java.util.Optional;

@Controller
@RequestMapping("/forgot-password")
public class ForgotPasswordController {

    private final UserService userService;
    private final EmailService emailService;

    public ForgotPasswordController(UserService userService, EmailService emailService) {
        this.userService = userService;
        this.emailService = emailService;
    }

    // --- 1. Select Method ---
    @GetMapping
    public String showMethodSelection() {
        return "auth/forgot-password-method";
    }

    // --- 2. Security Questions Flow ---
    @GetMapping("/questions")
    public String showQuestionsForm() {
        // Step 1: Just enter email
        return "auth/forgot-password-questions";
    }

    @PostMapping("/questions")
    public String processQuestionsEmail(@RequestParam String email, RedirectAttributes ra) {
        Optional<User> userOpt = userService.findByEmail(email);
        if (userOpt.isEmpty()) {
            ra.addFlashAttribute("error", "No account found with that email.");
            return "redirect:/forgot-password/questions";
        }
        return "redirect:/forgot-password/questions/verify?email=" + email;
    }

    @GetMapping("/questions/verify")
    public String showVerifyQuestions(@RequestParam String email, Model model, RedirectAttributes ra) {
        Optional<User> userOpt = userService.findByEmail(email);
        if (userOpt.isEmpty()) {
            ra.addFlashAttribute("error", "Session invalid.");
            return "redirect:/forgot-password/questions";
        }
        User user = userOpt.get();
        model.addAttribute("email", email);

        // Try to get questions from the list first (preferred)
        List<SecurityQuestion> questions = userService.getSecurityQuestions(user);
        String q1 = !questions.isEmpty() ? questions.get(0).getQuestion() : user.getSecurityQuestion1();
        String q2 = questions.size() > 1 ? questions.get(1).getQuestion() : user.getSecurityQuestion2();
        String q3 = questions.size() > 2 ? questions.get(2).getQuestion() : user.getSecurityQuestion3();

        model.addAttribute("question1", q1);
        model.addAttribute("question2", q2);
        model.addAttribute("question3", q3);
        return "auth/forgot-password-verify-questions";
    }

    @PostMapping("/questions/verify")
    public String verifyQuestions(@RequestParam String email,
            @RequestParam String answer1,
            @RequestParam String answer2,
            @RequestParam String answer3,
            HttpSession session,
            RedirectAttributes ra) {
        Optional<User> userOpt = userService.findByEmail(email);
        if (userOpt.isPresent()) {
            User user = userOpt.get();
            if (userService.verifySecurityAnswers(user, answer1, answer2, answer3)) {
                session.setAttribute("verifiedResetUser", email);
                return "redirect:/forgot-password/reset";
            }
        }
        ra.addFlashAttribute("error", "Incorrect answers. Please try again.");
        return "redirect:/forgot-password/questions/verify?email=" + email;
    }

    // --- 3. Email OTP Flow ---
    @GetMapping("/email")
    public String showEmailForm() {
        return "auth/forgot-password-email";
    }

    @PostMapping("/send-otp")
    public String sendOtp(@RequestParam String email, HttpSession session, RedirectAttributes ra) {
        Optional<User> userOpt = userService.findByEmail(email);
        if (userOpt.isPresent()) {
            User user = userOpt.get();
            String otp = userService.generateResetOtp(user);
            try {
                emailService.sendPasswordResetOtp(user.getEmail(), otp);
                session.setAttribute("resetEmail", email);
            } catch (Exception e) {
                e.printStackTrace();
                ra.addFlashAttribute("error", "Failed to send email. Check SMTP configuration.");
                return "redirect:/forgot-password/email";
            }
        }
        // Always redirect to verify-otp to prevent email enumeration, even if email
        // wasn't found
        ra.addFlashAttribute("success", "If an account with that email exists, an OTP has been sent.");
        return "redirect:/forgot-password/verify-otp";
    }

    @GetMapping("/verify-otp")
    public String showVerifyOtpForm(HttpSession session, Model model) {
        if (session.getAttribute("resetEmail") == null) {
            return "redirect:/forgot-password/email";
        }
        return "auth/forgot-password-verify-otp";
    }

    @PostMapping("/verify-otp")
    public String verifyOtp(@RequestParam String otp, HttpSession session, RedirectAttributes ra) {
        String email = (String) session.getAttribute("resetEmail");
        if (email == null)
            return "redirect:/forgot-password/email";

        Optional<User> userOpt = userService.findByEmail(email);
        if (userOpt.isPresent() && userService.verifyResetOtp(userOpt.get(), otp)) {
            session.setAttribute("verifiedResetUser", email);
            return "redirect:/forgot-password/reset";
        }

        ra.addFlashAttribute("error", "Invalid or expired OTP");
        return "redirect:/forgot-password/verify-otp";
    }

    // --- 4. Final Reset Flow ---
    @GetMapping("/reset")
    public String showResetForm(HttpSession session) {
        if (session.getAttribute("verifiedResetUser") == null) {
            return "redirect:/forgot-password";
        }
        return "auth/forgot-password-reset";
    }

    @PostMapping("/reset")
    public String processReset(@RequestParam("password") String newPassword,
            @RequestParam String confirmPassword,
            HttpSession session,
            RedirectAttributes ra) {

        String email = (String) session.getAttribute("verifiedResetUser");
        if (email == null) {
            return "redirect:/forgot-password";
        }

        if (!newPassword.equals(confirmPassword)) {
            ra.addFlashAttribute("error", "Passwords do not match");
            return "redirect:/forgot-password/reset";
        }

        Optional<User> userOpt = userService.findByEmail(email);
        if (userOpt.isPresent()) {
            userService.resetPassword(userOpt.get(), newPassword);
            session.removeAttribute("resetEmail");
            session.removeAttribute("verifiedResetUser");
            ra.addFlashAttribute("success", "Password has been reset successfully. Please log in.");
            return "redirect:/auth/login";
        }

        return "redirect:/forgot-password";
    }
}
