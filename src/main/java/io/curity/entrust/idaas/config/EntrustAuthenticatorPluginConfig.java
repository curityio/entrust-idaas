/*
 *  Copyright 2022 Curity AB
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package io.curity.entrust.idaas.config;

import se.curity.identityserver.sdk.config.Configuration;
import se.curity.identityserver.sdk.config.OneOf;
import se.curity.identityserver.sdk.config.annotation.DefaultBoolean;
import se.curity.identityserver.sdk.config.annotation.DefaultEnum;
import se.curity.identityserver.sdk.config.annotation.Description;
import se.curity.identityserver.sdk.service.HttpClient;
import se.curity.identityserver.sdk.service.Json;
import se.curity.identityserver.sdk.service.SessionManager;
import se.curity.identityserver.sdk.service.WebServiceClientFactory;
import se.curity.identityserver.sdk.service.authentication.AuthenticationRequirements;
import se.curity.identityserver.sdk.service.authentication.AuthenticatorExceptionFactory;
import se.curity.identityserver.sdk.service.authentication.AuthenticatorInformationProvider;

import java.util.List;
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

    AuthenticatorExceptionFactory getExceptionFactory();

    @Description("Additional scopes beyond 'openid' that should be requested")
    List<String> getAdditionalScopes();

    @Description("Additional claims that should be requested beyond 'sub' and those implicitly associated with the requested scopes ")
    List<String> getAdditionalClaims();

    @DefaultBoolean(true)
    @Description("Whether or not the prompt parameter should be relayed up to Entrust")
    boolean isRelayPrompt();

    AuthenticationRequirements getAuthenticationRequirements();

    IssuerOrEnvironmentAndName getIssuerOrEnvironmentAndName();

    @Description("The authentication method to use at the token endpoint")
    @DefaultEnum("BASIC")
    AuthenticationMethod getAuthenticationMethod();

    enum AuthenticationMethod
    {
        @Description("Use basic authentication")
        BASIC,

        @Description("Include the client ID and secret in the form body")
        FORM_POST
    }

    interface IssuerOrEnvironmentAndName extends OneOf
    {
        @Description("The URL of the issuer")
        Optional<String> getIssuer();

        @Description("The name and region of the environment of the issuer")
        Optional<EnvironmentAndName> getEnvironmentAndName();
    }

    enum Environment
    {
        @Description("Issuer is hosted in Germany")
        GERMANY,

        @Description("Issuer is hosted in the US")
        US,

        @Description("Issuer is hosted in Ireland")
        IRELAND
    }

    interface EnvironmentAndName
    {
        @Description("The region or environment where the issuer is hosted")
        Environment getEnvironment();

        @Description("The name of the issuer")
        String getName();
    }

    AuthenticatorInformationProvider getAuthenticatorInformationProvider();

    WebServiceClientFactory getWebServiceClientFactory();

    Json getJson();
}
