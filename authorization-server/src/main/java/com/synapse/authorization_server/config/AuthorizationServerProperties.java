package com.synapse.authorization_server.config;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "authorization-server")
public record AuthorizationServerProperties(
    String issuerUri,
    List<RegisteredClient> clients
) {
    public record RegisteredClient(
        String clientId,
        String clientSecret,
        List<String> scopes,
        long accessTokenTtlInHours
    ) {

    }
}
