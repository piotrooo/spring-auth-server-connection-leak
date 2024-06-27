package com.example.connectionleak.conf;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.convert.DurationUnit;

import java.time.Duration;

import static java.time.Duration.ofHours;
import static java.time.temporal.ChronoUnit.HOURS;

@ConfigurationProperties("instance-client")
public class InstanceClientProperties {
    private String clientId;

    private String clientSecret;

    private Token token = new Token();

    public String getClientId() {
        return clientId;
    }

    public InstanceClientProperties setClientId(String clientId) {
        this.clientId = clientId;
        return this;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public InstanceClientProperties setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
        return this;
    }

    public Token getToken() {
        return token;
    }

    public InstanceClientProperties setToken(Token token) {
        this.token = token;
        return this;
    }

    public static class Token {
        @DurationUnit(HOURS)
        private Duration accessTokenTimeToLive = ofHours(1);

        public Duration getAccessTokenTimeToLive() {
            return accessTokenTimeToLive;
        }

        public Token setAccessTokenTimeToLive(Duration accessTokenTimeToLive) {
            this.accessTokenTimeToLive = accessTokenTimeToLive;
            return this;
        }
    }
}
