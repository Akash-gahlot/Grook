package com.Grook.App.Controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import jakarta.servlet.http.HttpSession;

@Controller
public class HomeController {
    private static final Logger logger = LoggerFactory.getLogger(HomeController.class);

    @GetMapping({ "/", "/home" })
    public String home(Model model, Authentication authentication, HttpSession session) {
        String name = "Guest";

        System.out.println("=== Home Controller ===");
        System.out.println("Session ID: " + session.getId());

        // First try to get name from session
        String sessionName = (String) session.getAttribute("userName");
        if (sessionName != null && !sessionName.trim().isEmpty()) {
            name = sessionName;
            System.out.println("Name from session: " + name);
        }
        // If no session name, try authentication
        else if (authentication != null && authentication.isAuthenticated()) {
            System.out.println("Authentication present and authenticated");
            Object principal = authentication.getPrincipal();
            System.out.println("Principal class: " + (principal != null ? principal.getClass().getName() : "null"));

            if (principal instanceof OidcUser) {
                OidcUser oidcUser = (OidcUser) principal;
                System.out.println("=== Token Claims ===");
                oidcUser.getClaims().forEach((key, value) -> System.out.println(key + ": " + value));

                name = (String) oidcUser.getClaims().get("given_name");
                System.out.println("Name from claims: " + name);

                if (name == null || name.trim().isEmpty()) {
                    name = (String) oidcUser.getClaims().get("name");
                    System.out.println("Fallback name from claims: " + name);
                }
            }
        } else {
            System.out.println("No authentication or session name found");
        }

        System.out.println("Final name being set: " + name);
        model.addAttribute("name", name);
        return "home";
    }
}
