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
                // Try to get name from various claims
                name = oidcUser.getClaim("given_name");
                if (name == null) {
                    name = oidcUser.getClaim("name");
                }
                if (name == null) {
                    name = oidcUser.getPreferredUsername();
                }
                if (name == null) {
                    name = oidcUser.getSubject();
                }
                logger.info("Token claims: {}", oidcUser.getClaims());
                logger.info("Authenticated user name: {}", name);
            }
        } else {
            logger.info("User not authenticated, using default name");
        }

        model.addAttribute("name", name);
        return "home";
    }
}
