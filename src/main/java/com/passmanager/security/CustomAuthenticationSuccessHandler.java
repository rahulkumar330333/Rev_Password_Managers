package com.passmanager.security;

import com.passmanager.entity.User;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
        User user = userDetails.getUser();

        if (user.isTwoFactorEnabled()) {
            HttpSession session = request.getSession();
            // Store that we need 2FA verification
            session.setAttribute("TWO_FACTOR_CHECK_PENDING", true);
            session.setAttribute("TWO_FACTOR_USER_ID", user.getId());

            // Redirect to 2FA verification page
            response.sendRedirect("/auth/verify-2fa");
        } else {
            // Normal redirect to dashboard
            response.sendRedirect("/dashboard");
        }
    }
}
