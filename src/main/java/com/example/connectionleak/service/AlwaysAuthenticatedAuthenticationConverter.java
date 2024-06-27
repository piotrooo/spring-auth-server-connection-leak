package com.example.connectionleak.service;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.apache.commons.lang3.StringUtils.*;
import static org.springframework.security.oauth2.core.OAuth2ErrorCodes.INVALID_REQUEST;
import static org.springframework.security.oauth2.core.OAuth2ErrorCodes.UNSUPPORTED_RESPONSE_TYPE;
import static org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType.CODE;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.*;

public class AlwaysAuthenticatedAuthenticationConverter implements AuthenticationConverter {
    private static final String DEFAULT_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1";

    @Override
    public Authentication convert(HttpServletRequest request) {
        MultiValueMap<String, String> parameters = getQueryParameters(request);

        // response_type (REQUIRED)
        String responseType = parameters.getFirst(RESPONSE_TYPE);
        if (isBlank(responseType) || parameters.get(RESPONSE_TYPE).size() != 1) {
            throwError(INVALID_REQUEST, RESPONSE_TYPE);
        } else if (!responseType.equals(CODE.getValue())) {
            throwError(UNSUPPORTED_RESPONSE_TYPE, RESPONSE_TYPE);
        }

        // client_id (REQUIRED)
        String clientId = parameters.getFirst(CLIENT_ID);
        if (isBlank(clientId) || parameters.get(CLIENT_ID).size() != 1) {
            throwError(INVALID_REQUEST, CLIENT_ID);
        }

        // state (RECOMMENDED)
        String state = parameters.getFirst(STATE);
        if (isNotBlank(state) && parameters.get(STATE).size() != 1) {
            throwError(INVALID_REQUEST, STATE);
        }

        String principalName = "%s|%s|%s".formatted("client", "login", "100");
        Authentication principal = new AlwaysAuthenticatedAuthenticationToken(principalName, "client", "login", "100");

        String authorizationUri = request.getRequestURL().toString();
        return new OAuth2AuthorizationCodeRequestAuthenticationToken(authorizationUri, clientId, principal, null, state, null, new HashMap<>());
    }

    private static MultiValueMap<String, String> getQueryParameters(HttpServletRequest request) {
        Map<String, String[]> parameterMap = request.getParameterMap();
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        String queryString = isNotBlank(request.getQueryString()) ? request.getQueryString() : EMPTY;
        parameterMap.forEach((key, values) -> {
            if (queryString.contains(key)) {
                parameters.addAll(key, List.of(values));
            }
        });
        return parameters;
    }

    private static void throwError(String errorCode, String parameterName) {
        OAuth2Error error = new OAuth2Error(errorCode, "OAuth 2.0 Parameter: %s".formatted(parameterName), DEFAULT_ERROR_URI);
        throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
    }
}
