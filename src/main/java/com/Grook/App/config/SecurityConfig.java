package com.Grook.App.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

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
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/", "/home", "/error").permitAll()
                        .anyRequest().authenticated())
                .oauth2Login(oauth2 -> oauth2
                        .userInfoEndpoint(userInfo -> userInfo
                                .oidcUserService(this::oidcUserService))
                        .successHandler(successHandler())
                        .failureHandler((request, response, exception) -> {
                            logger.error("AUTH FAILED - Error type: " + exception.getClass().getName());
                            logger.error("AUTH FAILED - Error message: " + exception.getMessage());
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
                if (authentication.getPrincipal() instanceof OidcUser) {
                    OidcUser oidcUser = (OidcUser) authentication.getPrincipal();
                    logger.info("Authentication successful for user: {}", oidcUser.getClaims());
                    System.out.println("Authentication successful. Claims: " + oidcUser.getClaims());
                }
                response.sendRedirect(PRODUCTION_URL + "/home");
            }
        };
    }

    private OidcUser oidcUserService(OidcUserRequest userRequest) {
        try {
            logger.info("Processing OIDC user request");
            System.out.println("Token value: " + userRequest.getIdToken().getTokenValue());
            System.out.println("Claims: " + userRequest.getIdToken().getClaims());

            OAuth2UserService<OidcUserRequest, OidcUser> delegate = new org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService();
            return delegate.loadUser(userRequest);
        } catch (Exception e) {
            logger.error("Error processing OIDC user request: " + e.getMessage());
            System.out.println("Error processing OIDC user request: " + e.getMessage());
            throw e;
        }
    }
}