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

        if (principal != null) {
            String name = principal.getAttribute("name");
            logger.info("User name from principal: {}", name);
            model.addAttribute("name", name);
        } else {
            logger.warn("No principal found in the request");
        }

        return "home";
    }
}
