package io.curity.entrust.oidc.authentication;

import io.curity.entrust.oidc.config.EntrustAuthenticatorPluginConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.curity.identityserver.sdk.attribute.Attribute;
import se.curity.identityserver.sdk.authentication.AuthenticationResult;
import se.curity.identityserver.sdk.authentication.AuthenticatorRequestHandler;
import se.curity.identityserver.sdk.errors.ErrorCode;
import se.curity.identityserver.sdk.http.RedirectStatusCode;
import se.curity.identityserver.sdk.service.ExceptionFactory;
import se.curity.identityserver.sdk.service.authentication.AuthenticatorInformationProvider;
import se.curity.identityserver.sdk.web.Request;
import se.curity.identityserver.sdk.web.Response;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Random;
import java.util.Set;
import java.util.UUID;

import static io.curity.entrust.oidc.authentication.IssuerFactory.createIssuerFromEnvironmentAndName;
import static io.curity.entrust.oidc.descriptor.EntrustAuthenticatorPluginDescriptor.CALLBACK;
import static java.nio.charset.StandardCharsets.US_ASCII;
import static se.curity.identityserver.sdk.http.RedirectStatusCode.MOVED_TEMPORARILY;

public final class EntrustAuthenticatorRequestHandler implements AuthenticatorRequestHandler<Request>
{
    private static final Logger _logger = LoggerFactory.getLogger(EntrustAuthenticatorRequestHandler.class);
    private static final String AUTHORIZATION_ENDPOINT = "";

    private final EntrustAuthenticatorPluginConfig _config;
    private final AuthenticatorInformationProvider _authenticatorInformationProvider;
    private final ExceptionFactory _exceptionFactory;

    public EntrustAuthenticatorRequestHandler(EntrustAuthenticatorPluginConfig config)
    {
        _config = config;
        _exceptionFactory = config.getExceptionFactory();
        _authenticatorInformationProvider = config.getAuthenticatorInformationProvider();
    }

    @Override
    public Optional<AuthenticationResult> get(Request request, Response response)
    {
        _logger.debug("GET request received for authentication");

        String redirectUri = createRedirectUri();
        String codeVerifier = createCodeVerifier();
        Map<String, Collection<String>> queryStringArguments = new LinkedHashMap<>(6);

        _config.getSessionManager().put(Attribute.of("code_verifier", codeVerifier));

        _logger.debug("Code verifier = {}", codeVerifier);

        String codeChallenge = sha256Hash(codeVerifier);

        queryStringArguments.put("client_id", Set.of(_config.getClientId()));
        queryStringArguments.put("redirect_uri", Set.of(redirectUri));
        queryStringArguments.put("code_challenge", Set.of(codeChallenge));
        queryStringArguments.put("code_challenge_method", Set.of("S256"));
        queryStringArguments.put("response_type", Set.of("code"));
        queryStringArguments.put("scope", Set.of("openid"));

        _logger.debug("Redirecting to {} with query string arguments {}", AUTHORIZATION_ENDPOINT,
                queryStringArguments);

        throw _exceptionFactory.redirectException(createIssuerFromEnvironmentAndName(_config) + "/authorize",
                                                  MOVED_TEMPORARILY, queryStringArguments, false);
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

    private String sha256Hash(String codeVerifier)
    {
        MessageDigest messageDigest = getMessageDigest();
        byte[] digest = messageDigest.digest(codeVerifier.getBytes(US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

    private static MessageDigest getMessageDigest() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError(e);
        }
    }

    private String createRedirectUri()
    {
        try
        {
            URI authUri = _authenticatorInformationProvider.getFullyQualifiedAuthenticationUri();

            return new URL(authUri.toURL(), authUri.getPath() + "/" + CALLBACK).toString();
        }
        catch (MalformedURLException e)
        {
            throw _exceptionFactory.internalServerException(ErrorCode.INVALID_REDIRECT_URI,
                    "Could not create redirect URI");
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
