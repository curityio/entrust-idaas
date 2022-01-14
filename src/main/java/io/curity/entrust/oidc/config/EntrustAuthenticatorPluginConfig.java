package io.curity.entrust.oidc.config;


import se.curity.identityserver.sdk.config.Configuration;
import se.curity.identityserver.sdk.config.OneOf;
import se.curity.identityserver.sdk.config.annotation.DefaultBoolean;
import se.curity.identityserver.sdk.config.annotation.DefaultEnum;
import se.curity.identityserver.sdk.config.annotation.Description;
import se.curity.identityserver.sdk.service.ExceptionFactory;
import se.curity.identityserver.sdk.service.HttpClient;
import se.curity.identityserver.sdk.service.Json;
import se.curity.identityserver.sdk.service.OriginalQueryExtractor;
import se.curity.identityserver.sdk.service.SessionManager;
import se.curity.identityserver.sdk.service.WebServiceClientFactory;
import se.curity.identityserver.sdk.service.authentication.AuthenticatorInformationProvider;

import java.util.Optional;

@SuppressWarnings("InterfaceNeverImplemented")
public interface EntrustAuthenticatorPluginConfig extends Configuration
{
	@Description("Client ID")
    String getClientId();

    @Description("Secret secret")
    String getClientSecret();

    @Description("The HTTP client with any proxy and TLS settings that will be used to connect")
    Optional<HttpClient> getHttpClient();

    SessionManager getSessionManager();

    ExceptionFactory getExceptionFactory();

    @DefaultBoolean(true)
    @Description("Whether or not the prompt parameter should be relayed up to Entrust")
    boolean isRelayPrompt();

    OriginalQueryExtractor getOriginalQueryExtractor();

    IssuerOrEnvironmentAndName getIssuerOrEnvironmentAndName();

    @DefaultEnum("BASIC")
    AuthenticationMethod getAuthenticationMethod();

    enum AuthenticationMethod
    {
        BASIC, FORM_POST
    }

    interface IssuerOrEnvironmentAndName extends OneOf
    {
        Optional<String> getIssuer();

        Optional<EnvironmentAndName> getEnvironmentAndName();
    }

    enum Environment
    {
        GERMANY,
        US,
        IRELAND
    }

    interface EnvironmentAndName
    {
        Environment getEnvironment();

        String getName();
    }

    AuthenticatorInformationProvider getAuthenticatorInformationProvider();

    WebServiceClientFactory getWebServiceClientFactory();

    Json getJson();
}
