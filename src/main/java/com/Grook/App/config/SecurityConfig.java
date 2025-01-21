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
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
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

        // Get the Azure B2C client registration
        ClientRegistration azureClient = clientRegistrationRepository.findByRegistrationId("azure");
        if (azureClient != null) {
            logger.info("Found Azure B2C client registration with client ID: {}", azureClient.getClientId());
            System.out.println("Found Azure B2C client registration with client ID: " + azureClient.getClientId());
        }

        http
                .csrf(csrf -> csrf
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                        .ignoringRequestMatchers("/login/oauth2/code/*"))
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/", "/login", "/error", "/webjars/**", "/oauth2/**", "/login/oauth2/code/*")
                        .permitAll()
                        .anyRequest().authenticated())
                .oauth2Login(oauth2 -> oauth2
                        .loginPage("/login")
                        .defaultSuccessUrl("/home", true)
                        .failureUrl("/login?error=true")
                        .authorizationEndpoint(authorization -> authorization
                                .authorizationRequestResolver(customizeAuthorizationRequestResolver(resolver)))
                        .userInfoEndpoint(userInfo -> userInfo
                                .userAuthoritiesMapper(authorities -> authorities))
                        .successHandler((request, response, authentication) -> {
                            try {
                                logger.info("Starting token validation...");
                                System.out.println("Starting token validation...");

                                // Log session ID for debugging
                                HttpSession session = request.getSession(false);
                                if (session != null) {
                                    logger.info("Session ID: {}", session.getId());
                                    System.out.println("Session ID: " + session.getId());
                                }

                                if (authentication.getPrincipal() != null) {
                                    logger.info("User authenticated successfully: {}", authentication.getName());
                                    System.out.println("User authenticated successfully: " + authentication.getName());

                                    authentication.getAuthorities().forEach(authority -> {
                                        logger.info("Authority: {}", authority);
                                        System.out.println("Authority: " + authority);
                                    });

                                    if (authentication.getDetails() != null) {
                                        logger.info("Authentication details: {}", authentication.getDetails());
                                        System.out.println("Authentication details: " + authentication.getDetails());
                                    }

                                    if (authentication.getCredentials() != null) {
                                        logger.info("Credentials type: {}",
                                                authentication.getCredentials().getClass().getName());
                                        System.out.println("Credentials type: "
                                                + authentication.getCredentials().getClass().getName());
                                    }
                                } else {
                                    throw new OAuth2AuthenticationException(
                                            new OAuth2Error("invalid_token", "No principal found", null));
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
                            logger.error("AUTH FAILED - Stack trace: ", exception);

                            System.out.println("AUTH FAILED - Error type: " + exception.getClass().getName());
                            System.out.println("AUTH FAILED - Error message: " + exception.getMessage());

                            // Log session ID for debugging
                            HttpSession session = request.getSession(false);
                            if (session != null) {
                                logger.info("Session ID: {}", session.getId());
                                System.out.println("Session ID: " + session.getId());
                            }

                            logger.info("Request URI: {}", request.getRequestURI());
                            logger.info("Request Parameters: {}", request.getParameterMap());

                            java.util.Collections.list(request.getHeaderNames()).forEach(headerName -> {
                                logger.info("Header {}: {}", headerName, request.getHeader(headerName));
                                System.out.println("Header " + headerName + ": " + request.getHeader(headerName));
                            });

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

        logger.info("Customizing authorization request for client ID: {}", auth2Request.getClientId());
        System.out.println("Customizing authorization request for client ID: " + auth2Request.getClientId());

        Consumer<Map<String, Object>> parametersConsumer = parameters -> {
            // Keep original parameters
            parameters.putAll(auth2Request.getAdditionalParameters());

            // Add B2C specific parameters
            parameters.put("resource", "https://hcliamtrainingb2c.onmicrosoft.com");
            parameters.put("response_mode", "form_post");
            parameters.put("p", "B2C_1A_FG_HCL_SIGNUP_SIGNIN");

            // Don't override these as they should come from the client registration
            if (!parameters.containsKey("scope")) {
                parameters.put("scope", "openid profile email");
            }
            if (!parameters.containsKey("response_type")) {
                parameters.put("response_type", "code");
            }

            // Log all parameters for debugging
            parameters.forEach((key, value) -> {
                logger.info("Parameter {} = {}", key, value);
                System.out.println("Parameter " + key + " = " + value);
            });
        };

        return OAuth2AuthorizationRequest.from(auth2Request)
                .additionalParameters(parametersConsumer)
                .build();
    }
}