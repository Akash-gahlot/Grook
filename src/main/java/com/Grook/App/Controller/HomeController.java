package com.Grook.App.Controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {

    private static final Logger logger = LoggerFactory.getLogger(HomeController.class);

    @GetMapping("/home")
    public String home(@AuthenticationPrincipal OAuth2User principal, Model model) {
        logger.info("Accessing home page. User authenticated: {}", principal != null);
        System.out.println("HOME - Accessing home page. User authenticated: " + (principal != null));

        if (principal != null) {
            // Log all available attributes
            principal.getAttributes().forEach((key, value) -> {
                logger.info("OAuth2 Attribute - {}: {}", key, value);
                System.out.println("OAuth2 Attribute - " + key + ": " + value);
            });

            // Get essential attributes
            String name = principal.getAttribute("name");
            String email = principal.getAttribute("email");
            String sub = principal.getAttribute("sub");

            logger.info("User details - Name: {}, Email: {}, Sub: {}", name, email, sub);
            System.out.println("User details - Name: " + name + ", Email: " + email + ", Sub: " + sub);

            // Add attributes to model
            model.addAttribute("name", name);
            model.addAttribute("email", email);
            model.addAttribute("sub", sub);
            model.addAttribute("attributes", principal.getAttributes());
        } else {
            logger.warn("No principal found in the request");
            System.out.println("WARNING - No principal found in the request");
        }

        return "home";
    }
}
