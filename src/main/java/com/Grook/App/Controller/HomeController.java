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
        String logMessage = String.format("HOME PAGE ACCESS - User authenticated: %s", principal != null);
        logger.info(logMessage);
        System.out.println(logMessage);

        if (principal != null) {
            String name = principal.getAttribute("name");
            String userLogMessage = String.format("USER INFO - Name: %s, All attributes: %s",
                    name, principal.getAttributes());
            logger.info(userLogMessage);
            System.out.println(userLogMessage);

            model.addAttribute("name", name);
        } else {
            System.out.println("WARNING - No principal found in the request");
        }

        return "home";
    }
}
