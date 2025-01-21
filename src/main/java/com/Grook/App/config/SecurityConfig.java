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
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
import java.util.function.Consumer;

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
        String authorizationRequestBaseUri = "/oauth2/authorization";
        final OAuth2AuthorizationRequestResolver resolver = new DefaultOAuth2AuthorizationRequestResolver(
                clientRegistrationRepository, authorizationRequestBaseUri);

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
                        .authorizationEndpoint(authorization -> authorization
                                .authorizationRequestResolver(customizeAuthorizationRequestResolver(resolver)))
                        .successHandler((request, response, authentication) -> {
                            try {
                                logger.info("Token validation successful");
                                System.out.println("Token validation successful");

                                if (authentication.getPrincipal() != null) {
                                    logger.info("User authenticated successfully: {}", authentication.getName());
                                    System.out.println("User authenticated successfully: " + authentication.getName());
                                }

                                response.sendRedirect("/home");
                            } catch (Exception e) {
                                logger.error("Error in success handler: " + e.getMessage(), e);
                                System.out.println("Error in success handler: " + e.getMessage());
                                response.sendRedirect("/login?error=true");
                            }
                        })
                        .failureHandler((request, response, exception) -> {
                            logger.error("AUTH FAILED - Error type: " + exception.getClass().getName());
                            logger.error("AUTH FAILED - Error message: " + exception.getMessage());
                            System.out.println("AUTH FAILED - Error type: " + exception.getClass().getName());
                            System.out.println("AUTH FAILED - Error message: " + exception.getMessage());
                            response.sendRedirect("/login?error=true");
                        }))
                .logout(logout -> logout
                        .logoutSuccessUrl("/")
                        .invalidateHttpSession(true)
                        .clearAuthentication(true)
                        .deleteCookies("JSESSIONID"));

        return http.build();
    }

    private OAuth2AuthorizationRequestResolver customizeAuthorizationRequestResolver(
            OAuth2AuthorizationRequestResolver resolver) {
        return new OAuth2AuthorizationRequestResolver() {
            @Override
            public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
                OAuth2AuthorizationRequest auth2Request = resolver.resolve(request);
                return auth2Request != null ? customizeAuthorizationRequest(auth2Request) : null;
            }

            @Override
            public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
                OAuth2AuthorizationRequest auth2Request = resolver.resolve(request, clientRegistrationId);
                return auth2Request != null ? customizeAuthorizationRequest(auth2Request) : null;
            }
        };
    }

    private OAuth2AuthorizationRequest customizeAuthorizationRequest(OAuth2AuthorizationRequest auth2Request) {
        if (auth2Request == null) {
            return null;
        }

        Consumer<Map<String, Object>> parametersConsumer = parameters -> {
            parameters.put("resource", "https://hcliamtrainingb2c.onmicrosoft.com");
            parameters.put("response_mode", "form_post");
        };

        return OAuth2AuthorizationRequest.from(auth2Request)
                .additionalParameters(parametersConsumer)
                .build();
    }
}