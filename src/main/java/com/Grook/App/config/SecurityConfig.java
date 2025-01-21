package com.Grook.App.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import jakarta.servlet.http.HttpServletRequest;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private static final Logger logger = LoggerFactory.getLogger(SecurityConfig.class);
    private final ClientRegistrationRepository clientRegistrationRepository;

    public SecurityConfig(ClientRegistrationRepository clientRegistrationRepository) {
        this.clientRegistrationRepository = clientRegistrationRepository;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/", "/login", "/error", "/webjars/**", "/oauth2/**").permitAll()
                        .anyRequest().authenticated())
                .oauth2Login(oauth2 -> oauth2
                        .loginPage("/login")
                        .defaultSuccessUrl("/home", true)
                        .failureUrl("/login?error=true")
                        .successHandler((request, response, authentication) -> {
                            try {
                                String userName = authentication.getName();
                                OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();

                                // Log request details
                                logRequestDetails(request);

                                // Log authentication details
                                String logMessage = String.format("AUTH SUCCESS - User: %s, Attributes: %s",
                                        userName, oauth2User.getAttributes());
                                logger.info(logMessage);
                                System.out.println(logMessage);

                                response.sendRedirect("/home");
                            } catch (Exception e) {
                                logger.error("Error in success handler: " + e.getMessage(), e);
                                System.out.println("Error in success handler: " + e.getMessage());
                                response.sendRedirect("/login?error=true");
                            }
                        })
                        .failureHandler((request, response, exception) -> {
                            // Log request details
                            logRequestDetails(request);

                            // Log detailed error information
                            logger.error("AUTH FAILED - Error type: " + exception.getClass().getName());
                            logger.error("AUTH FAILED - Error message: " + exception.getMessage());
                            logger.error("AUTH FAILED - Stack trace: ", exception);

                            // Log in console for immediate visibility
                            System.out.println("AUTH FAILED - Error type: " + exception.getClass().getName());
                            System.out.println("AUTH FAILED - Error message: " + exception.getMessage());

                            response.sendRedirect("/login?error=true");
                        }))
                .logout(logout -> {
                    logout.logoutSuccessUrl("/")
                            .invalidateHttpSession(true)
                            .clearAuthentication(true)
                            .deleteCookies("JSESSIONID")
                            .permitAll();
                    System.out.println("LOGOUT - User logged out successfully");
                });
        return http.build();
    }

    private void logRequestDetails(HttpServletRequest request) {
        logger.info("Request URI: " + request.getRequestURI());
        logger.info("Request URL: " + request.getRequestURL());
        logger.info("Query String: " + request.getQueryString());
        logger.info("Remote Address: " + request.getRemoteAddr());
        logger.info("Headers:");
        java.util.Enumeration<String> headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String headerName = headerNames.nextElement();
            logger.info(headerName + ": " + request.getHeader(headerName));
        }
    }
}