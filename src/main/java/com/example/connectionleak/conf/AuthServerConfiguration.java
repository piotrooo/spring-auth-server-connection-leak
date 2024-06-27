package com.example.connectionleak.conf;

import com.example.connectionleak.service.AlwaysAuthenticatedAuthenticationConverter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;

import static java.time.Duration.ofHours;
import static java.util.UUID.randomUUID;
import static org.springframework.core.Ordered.HIGHEST_PRECEDENCE;
import static org.springframework.security.oauth2.core.AuthorizationGrantType.AUTHORIZATION_CODE;
import static org.springframework.security.oauth2.core.AuthorizationGrantType.REFRESH_TOKEN;
import static org.springframework.security.oauth2.core.ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
import static org.springframework.security.oauth2.server.authorization.client.RegisteredClient.withId;

@Configuration
public class AuthServerConfiguration {
    @Bean
    public RegisteredClientRepository registeredClientRepository(
            InstanceClientProperties instanceClientProperties,
            PasswordEncoder passwordEncoder,
            JdbcOperations jdbcOperations
    ) {
        String clientId = instanceClientProperties.getClientId();
        String clientSecret = passwordEncoder.encode(instanceClientProperties.getClientSecret());

        JdbcRegisteredClientRepository registeredClientRepository = new JdbcRegisteredClientRepository(jdbcOperations);
        RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);

        String id = registeredClient == null ? randomUUID().toString() : registeredClient.getId();
        RegisteredClient instanceRegisteredClient = withId(id)
                .clientId(clientId)
                .clientSecret(clientSecret)
                .clientAuthenticationMethod(CLIENT_SECRET_BASIC)
                .authorizationGrantType(AUTHORIZATION_CODE)
                .authorizationGrantType(REFRESH_TOKEN)
                // This 'fake' URI is not utilized in the current OAuth Authorization Code Flow.
                // Client instance is only parsing the Location header instead of following redirects.
                // This is a temporary solution until user authentication will be implemented directly in auth-service.
                .redirectUri("http://127.0.0.1:9000")
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(instanceClientProperties.getToken().getAccessTokenTimeToLive())
                        .refreshTokenTimeToLive(ofHours(24))
                        .reuseRefreshTokens(false)
                        .build()
                )
                .build();

        registeredClientRepository.save(instanceRegisteredClient);

        return registeredClientRepository;
    }

    @Bean
    public OAuth2AuthorizationService oAuth2AuthorizationService(
            JdbcOperations jdbcOperations,
            RegisteredClientRepository registeredClientRepository
    ) {
        return new JdbcOAuth2AuthorizationService(jdbcOperations, registeredClientRepository);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }

    @Bean
    @Order(HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .authorizationEndpoint(authorizationEndpoint -> authorizationEndpoint
                        .authorizationRequestConverter(new AlwaysAuthenticatedAuthenticationConverter())
                );
        return http
                .csrf(AbstractHttpConfigurer::disable)
                .build();
    }

//    @Bean
//    public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer() {
//        return (context) -> {
//            if (context.getTokenType() == ACCESS_TOKEN) {
//                context.getClaims().claims((claims) -> {
//                    AlwaysAuthenticatedAuthenticationToken authorization = context.getPrincipal();
//                    long userId = Long.parseLong(authorization.getUserId());
//                    CurrentUser user = new CurrentUser(authorization.getClient(), userId, authorization.getLogin());
//                    claims.put(USER, user);
//                });
//            }
//        };
//    }
}
