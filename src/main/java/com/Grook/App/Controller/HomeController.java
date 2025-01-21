package com.Grook.App.Controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {
    private static final Logger logger = LoggerFactory.getLogger(HomeController.class);

    @GetMapping({ "/", "/home" })
    public String home(Model model, Authentication authentication) {
        String name = "Guest";

        System.out.println("=== Starting Home Controller ===");
        System.out.println("Authentication object present: " + (authentication != null));

        if (authentication != null) {
            System.out.println("Is Authenticated: " + authentication.isAuthenticated());
            System.out.println("Authentication class: " + authentication.getClass().getName());
            System.out.println("Authentication details: " + authentication.getDetails());

            Object principal = authentication.getPrincipal();
            System.out.println("Principal class: " + (principal != null ? principal.getClass().getName() : "null"));

            if (principal instanceof OidcUser) {
                OidcUser oidcUser = (OidcUser) principal;
                System.out.println("=== Token Claims ===");
                oidcUser.getClaims().forEach((key, value) -> System.out.println(key + ": " + value));

                // Try all possible name claims
                name = (String) oidcUser.getClaims().get("given_name");
                System.out.println("Tried given_name: " + name);

                if (name == null || name.trim().isEmpty()) {
                    name = (String) oidcUser.getClaims().get("name");
                    System.out.println("Tried name: " + name);
                }

                if (name == null || name.trim().isEmpty()) {
                    name = oidcUser.getName();
                    System.out.println("Tried getName(): " + name);
                }

                System.out.println("Final name value: " + name);
            } else {
                System.out.println("Principal is not OidcUser");
            }
        } else {
            System.out.println("No authentication object present");
        }

        System.out.println("Setting name attribute to: " + name);
        model.addAttribute("name", name);
        return "home";
    }
}
