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

        if (authentication != null && authentication.isAuthenticated()) {
            Object principal = authentication.getPrincipal();
            if (principal instanceof OidcUser) {
                OidcUser oidcUser = (OidcUser) principal;
                logger.info("All claims from token: {}", oidcUser.getClaims());
                System.out.println("All claims from token: " + oidcUser.getClaims());

                // Get the name from given_name claim
                name = (String) oidcUser.getClaims().get("given_name");
                logger.info("Extracted given_name: {}", name);
                System.out.println("Extracted given_name: " + name);

                if (name == null) {
                    name = (String) oidcUser.getClaims().get("name");
                    logger.info("Falling back to name claim: {}", name);
                }
            } else {
                logger.warn("Principal is not an instance of OidcUser: {}", principal.getClass());
                System.out.println("Principal is not an instance of OidcUser: " + principal.getClass());
            }
        } else {
            logger.info("User not authenticated, using default name");
            System.out.println("User not authenticated, using default name");
        }

        model.addAttribute("name", name);
        return "home";
    }
}
