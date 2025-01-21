package com.Grook.App.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.core.authority.AuthorityUtils;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private static final Logger logger = LoggerFactory.getLogger(SecurityConfig.class);
    private final ClientRegistrationRepository clientRegistrationRepository;
    private static final String PRODUCTION_URL = "https://grook-production.up.railway.app";

    public SecurityConfig(ClientRegistrationRepository clientRegistrationRepository) {
        this.clientRegistrationRepository = clientRegistrationRepository;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .cors(cors -> cors.disable())
                .headers(headers -> headers.frameOptions().disable())
                .authorizeHttpRequests(authorize -> authorize
                        .anyRequest().permitAll())
                .oauth2Login(oauth2 -> oauth2
                        .userInfoEndpoint(userInfo -> userInfo
                                .oidcUserService(this::oidcUserService))
                        .successHandler(successHandler())
                        .failureHandler((request, response, exception) -> {
                            logger.error("AUTH FAILED - Error type: " + exception.getClass().getName());
                            logger.error("AUTH FAILED - Error message: " + exception.getMessage());
                            System.out.println("AUTH FAILED - Stack trace:");
                            exception.printStackTrace();
                            response.sendRedirect(PRODUCTION_URL + "/home");
                        }));

        return http.build();
    }

    private AuthenticationSuccessHandler successHandler() {
        return new AuthenticationSuccessHandler() {
            @Override
            public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                    org.springframework.security.core.Authentication authentication)
                    throws IOException, ServletException {
                System.out.println("=== Authentication Success Handler ===");

                if (authentication.getPrincipal() instanceof OidcUser) {
                    OidcUser oidcUser = (OidcUser) authentication.getPrincipal();
                    Map<String, Object> claims = oidcUser.getClaims();
                    System.out.println("=== Token Claims ===");
                    claims.forEach((key, value) -> System.out.println(key + ": " + value));

                    String name = (String) claims.get("given_name");
                    if (name != null && !name.trim().isEmpty()) {
                        System.out.println("Setting userName in session: " + name);
                        request.getSession().setAttribute("userName", name);
                    }
                }
                response.sendRedirect(PRODUCTION_URL + "/home");
            }
        };
    }

    private OidcUser oidcUserService(OidcUserRequest userRequest) {
        try {
            System.out.println("=== Processing OIDC User Request ===");
            Map<String, Object> claims = userRequest.getIdToken().getClaims();
            System.out.println("=== ID Token Claims ===");
            claims.forEach((key, value) -> System.out.println(key + ": " + value));

            return new DefaultOidcUser(
                    AuthorityUtils.createAuthorityList("ROLE_USER"),
                    userRequest.getIdToken(),
                    "given_name");
        } catch (Exception e) {
            System.out.println("Error in oidcUserService: " + e.getMessage());
            e.printStackTrace();
            throw e;
        }
    }
}