package com.passmanager.controller;

import com.passmanager.entity.User;
import com.passmanager.service.UserService;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

@ControllerAdvice
public class GlobalControllerAdvice {

    private final UserService userService;

    public GlobalControllerAdvice(UserService userService) {
        this.userService = userService;
    }

    @ModelAttribute
    public void addUserToModel(Model model) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.isAuthenticated() && !auth.getPrincipal().equals("anonymousUser")) {
            try {
                User user = userService.getCurrentUser();
                if (user != null) {
                    model.addAttribute("user", user);
                }
            } catch (Exception e) {
                // Silently omit if user not found or errors occur
            }
        }
    }
}
