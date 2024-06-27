package com.example.connectionleak.service;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import org.springframework.security.authentication.AbstractAuthenticationToken;

import static java.util.Collections.emptyList;
import static org.apache.commons.lang3.StringUtils.EMPTY;

@JsonDeserialize
@JsonIgnoreProperties(ignoreUnknown = true)
public class AlwaysAuthenticatedAuthenticationToken extends AbstractAuthenticationToken {
    private final String principal;
    private final String client;
    private final String login;
    private final String userId;

    public AlwaysAuthenticatedAuthenticationToken(
            @JsonProperty("principal") String principal,
            @JsonProperty("client") String client,
            @JsonProperty("login") String login,
            @JsonProperty("userId") String userId
    ) {
        super(emptyList());

        this.principal = principal;
        this.client = client;
        this.login = login;
        this.userId = userId;
        setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return EMPTY;
    }

    @Override
    @JsonProperty("principal")
    public Object getPrincipal() {
        return principal;
    }

    @JsonProperty("client")
    public String getClient() {
        return client;
    }

    @JsonProperty("login")
    public String getLogin() {
        return login;
    }

    @JsonProperty("userId")
    public String getUserId() {
        return userId;
    }
}
