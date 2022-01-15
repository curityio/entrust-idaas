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

package io.curity.entrust.oidc.authentication;

import io.curity.entrust.oidc.config.EntrustAuthenticatorPluginConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.curity.identityserver.sdk.Nullable;
import se.curity.identityserver.sdk.attribute.Attribute;
import se.curity.identityserver.sdk.authentication.AuthenticationResult;
import se.curity.identityserver.sdk.authentication.AuthenticatorRequestHandler;
import se.curity.identityserver.sdk.service.ExceptionFactory;
import se.curity.identityserver.sdk.web.Request;
import se.curity.identityserver.sdk.web.Response;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Random;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static io.curity.entrust.oidc.authentication.Util.createIssuerFromEnvironmentAndName;
import static io.curity.entrust.oidc.authentication.Util.createRedirectUri;
import static java.nio.charset.StandardCharsets.US_ASCII;
import static se.curity.identityserver.sdk.http.RedirectStatusCode.MOVED_TEMPORARILY;

public final class EntrustAuthenticatorRequestHandler implements AuthenticatorRequestHandler<Request>
{
    private static final Logger _logger = LoggerFactory.getLogger(EntrustAuthenticatorRequestHandler.class);

    private final EntrustAuthenticatorPluginConfig _config;
    private final ExceptionFactory _exceptionFactory;

    public EntrustAuthenticatorRequestHandler(EntrustAuthenticatorPluginConfig config)
    {
        _config = config;
        _exceptionFactory = config.getExceptionFactory();
    }

    @Override
    public Optional<AuthenticationResult> get(Request request, Response response)
    {
        _logger.debug("GET request received for authentication");

        String redirectUri = createRedirectUri(_config);
        String codeVerifier = createCodeVerifier();
        Map<String, Collection<String>> queryStringArguments = new LinkedHashMap<>(7);

        _config.getSessionManager().put(Attribute.of("code_verifier", codeVerifier));

        _logger.debug("Code verifier = {}", codeVerifier);

        String codeChallenge = sha256Hash(codeVerifier);

        String scope = Stream.concat(_config.getAdditionalScopes().stream(), Stream.of("openid"))
                .collect(Collectors.joining(" "));

        _logger.trace("Scope that will be requested = {}", scope);

        queryStringArguments.put("client_id", Set.of(_config.getClientId()));
        queryStringArguments.put("redirect_uri", Set.of(redirectUri));
        queryStringArguments.put("code_challenge", Set.of(codeChallenge));
        queryStringArguments.put("code_challenge_method", Set.of("S256"));
        queryStringArguments.put("response_type", Set.of("code"));
        queryStringArguments.put("scope", Set.of(scope));

        @Nullable
        String prompt = _config.getOriginalQueryExtractor().getAuthorizationRequestQueryParameterValue("prompt");

        if (prompt != null && _config.isRelayPrompt())
        {
            queryStringArguments.put("prompt", Set.of(prompt));
        }

        String authorizationEndpoint = createIssuerFromEnvironmentAndName(_config) + "/authorize";

        _logger.debug("Redirecting to {} with query string arguments {}", authorizationEndpoint,
                queryStringArguments);

        throw _exceptionFactory.redirectException(authorizationEndpoint, MOVED_TEMPORARILY, queryStringArguments, false);
    }

    private static String createCodeVerifier()
    {
        int codeVerifierLength = 128;
        char[] allAllowed = "abcdefghijklmnopqrstuvwxyzABCDEFGJKLMNPRSTUVWXYZ0123456789".toCharArray();
        int allAllowedLength = allAllowed.length;
        Random random = new SecureRandom();
        StringBuilder codeVerifier = new StringBuilder();

        for (int i = 0; i < codeVerifierLength; i++)
        {
            codeVerifier.append(allAllowed[random.nextInt(allAllowedLength)]);
        }

        return codeVerifier.toString();
    }

    private static String sha256Hash(String codeVerifier)
    {
        MessageDigest messageDigest = getMessageDigest();
        byte[] digest = messageDigest.digest(codeVerifier.getBytes(US_ASCII));

        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

    private static MessageDigest getMessageDigest()
    {
        try
        {
            return MessageDigest.getInstance("SHA-256");
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new AssertionError(e);
        }
    }

    @Override
    public Optional<AuthenticationResult> post(Request request, Response response)
    {
        throw _exceptionFactory.methodNotAllowed();
    }

    @Override
    public Request preProcess(Request request, Response response)
    {
        return request;
    }
}
