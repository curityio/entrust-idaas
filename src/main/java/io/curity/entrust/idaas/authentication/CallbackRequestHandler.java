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

package io.curity.entrust.idaas.authentication;

import io.curity.entrust.idaas.config.EntrustAuthenticatorPluginConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.curity.identityserver.sdk.Nullable;
import se.curity.identityserver.sdk.attribute.AuthenticationAttributes;
import se.curity.identityserver.sdk.attribute.ContextAttributes;
import se.curity.identityserver.sdk.attribute.SubjectAttributes;
import se.curity.identityserver.sdk.authentication.AuthenticationResult;
import se.curity.identityserver.sdk.authentication.AuthenticatorRequestHandler;
import se.curity.identityserver.sdk.errors.ErrorCode;
import se.curity.identityserver.sdk.http.HttpRequest;
import se.curity.identityserver.sdk.http.HttpResponse;
import se.curity.identityserver.sdk.http.MultipleHeadersException;
import se.curity.identityserver.sdk.service.HttpClient;
import se.curity.identityserver.sdk.service.Json;
import se.curity.identityserver.sdk.service.WebServiceClient;
import se.curity.identityserver.sdk.service.WebServiceClientFactory;
import se.curity.identityserver.sdk.service.authentication.AuthenticatorExceptionFactory;
import se.curity.identityserver.sdk.service.authentication.AuthenticatorInformationProvider;
import se.curity.identityserver.sdk.web.Request;
import se.curity.identityserver.sdk.web.Response;

import java.net.URI;
import java.util.Base64;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static io.curity.entrust.idaas.authentication.Util.createIssuerFromEnvironmentAndName;
import static io.curity.entrust.idaas.authentication.Util.createRedirectUri;
import static io.curity.entrust.idaas.config.EntrustAuthenticatorPluginConfig.AuthenticationMethod.FORM_POST;
import static java.nio.charset.StandardCharsets.UTF_8;
import static se.curity.identityserver.sdk.http.HttpRequest.createFormUrlEncodedBodyProcessor;

public final class CallbackRequestHandler implements AuthenticatorRequestHandler<CallbackRequestModel>
{
    private final static Logger _logger = LoggerFactory.getLogger(CallbackRequestHandler.class);

    private final AuthenticatorExceptionFactory _exceptionFactory;
    private final EntrustAuthenticatorPluginConfig _config;
    private final Json _json;
    private final WebServiceClientFactory _webServiceClientFactory;
    private final boolean _isFormPost;

    public CallbackRequestHandler(EntrustAuthenticatorPluginConfig config)
    {
        _exceptionFactory = config.getExceptionFactory();
        _config = config;
        _json = config.getJson();
        _webServiceClientFactory = config.getWebServiceClientFactory();
        _isFormPost = _config.getAuthenticationMethod() == FORM_POST;
    }

    @Override
    public CallbackRequestModel preProcess(Request request, Response response)
    {
        if (request.isGetRequest())
        {
            return new CallbackRequestModel(request);
        } else
        {
            throw _exceptionFactory.methodNotAllowed();
        }
    }

    @Override
    public Optional<AuthenticationResult> post(CallbackRequestModel requestModel, Response response)
    {
        throw _exceptionFactory.methodNotAllowed();
    }

    @Override
    public Optional<AuthenticationResult> get(CallbackRequestModel requestModel, Response response)
    {
        handleError(requestModel);

        Map<String, ?> tokenResponseData = redeemCodeForTokens(requestModel);
        String accessToken = Objects.toString(tokenResponseData.get("access_token"));
        Map<String, ?> idTokenJson = getIdTokenJson(tokenResponseData);
        AuthenticationAttributes attributes = AuthenticationAttributes.of(
                SubjectAttributes.of(getSubjectAttributes(idTokenJson, accessToken)),
                ContextAttributes.of(getContextAttributes(idTokenJson)));

        _logger.trace("Entrust Access Token = {}", accessToken);

        return Optional.of(new AuthenticationResult(attributes));
    }

    private Map<String, ?> getSubjectAttributes(Map<String, ?> idTokenJson, String accessToken)
    {
        // Pass through all claims received from Entrust except system claims and ones with a null value
        // Also pass through user info if configured to call that

        Set<String> systemClaimNames = Set.of("iss", "aud", "exp", "iat", "auth_time", "nonce", "acr",
                                              "amr", "azp", "nbf", "jti");
        Map<String, ?> userInfo = getUserInfo(accessToken);

        Map<String, ?> subjectAttributes = Stream.concat(idTokenJson.entrySet().stream(), userInfo.entrySet().stream())
                .filter(it -> it.getValue() != null && !systemClaimNames.contains(it.getKey()))
                .map(it ->
                     {
                         if ("sub".equals(it.getKey()))
                         {
                             return Map.entry("subject", it.getValue());
                         }
                         return it;
                     }).collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue,
                                                 // *OBS* User info supersedes if present in both
                                                 (idTokenValue, userInfoValue) -> userInfoValue));

        if (_logger.isDebugEnabled())
        {
            _logger.debug("ID token{}claims from Entrust = {}, resulting subject attributes = {}",
                          _config.getAdditionalScopes().size() > 0 ? " and user info " : " ",
                          idTokenJson, subjectAttributes);
        }

        return subjectAttributes;
    }

    private Map<String, ?> getIdTokenJson(Map<String, ?> tokenResponseData)
    {
        return getTokenJson(tokenResponseData.get("id_token").toString());
    }

    private Map<String, ?> getTokenJson(String encodedToken)
    {
        // Why do we not check the signature of this token? See section 3.1.3.7.6 of OIDC core.
        String[] encodedBodyParts = encodedToken.split("\\.", 3);

        if (encodedBodyParts.length != 3)
        {
            _logger.warn("Expected a signed JWT (JWS), but didn't find one. Value = {}", encodedToken);

            throw _exceptionFactory.internalServerException(ErrorCode.EXTERNAL_SERVICE_ERROR);
        }

        String encodedBody = encodedBodyParts[1];
        String tokenBody = new String(Base64.getDecoder().decode(encodedBody));

        return _json.fromJson(tokenBody);
    }

    private Map<String, ?> getUserInfo(String accessToken)
    {
        if (_config.getAdditionalScopes().isEmpty())
        {
            _logger.debug("Not fetching user info because additional scope is empty");

            return Map.of();
        }

        _logger.debug("Fetching user info");

        // Fetch user info
        HttpResponse userInfoResponse = getWebServiceClient()
                .withPath("/userinfo")
                .request()
                .header("Authorization", "Bearer " + accessToken)
                .get()
                .response();

        throwIfServerError(userInfoResponse, "Got an error response from user info endpoint");

        Map<String, ?> userInfoJson = parseUserInfoResponse(userInfoResponse);

        _logger.debug("User info = {}", userInfoJson);

        return userInfoJson;
    }

    private Map<String, ?> parseUserInfoResponse(HttpResponse userInfoResponse)
    {
        Map<String, ?> userInfoJson;
        String contentType = getContentType(userInfoResponse)
                .replace(" ", ""); // Just in case content-type is something like "application / json"

        if (contentType.startsWith("application/json"))
        {
            userInfoJson = userInfoResponse.body((HttpResponse.asJsonObject(_json)));
        }
        else if (contentType.startsWith("application/jwt"))
        {
            userInfoJson = getTokenJson(userInfoResponse.body(HttpResponse.asString()));
        }
        else
        {
            _logger.warn("Entrust returned an unexpected content type: {}", contentType);

            userInfoJson = Map.of();
        }

        return userInfoJson;
    }

    private String getContentType(HttpResponse userInfoResponse)
    {
        try
        {
            @Nullable
            String contentType = userInfoResponse.headers().singleValueOrError("Content-Type");

            if (contentType == null)
            {
                _logger.warn("Entrust did not return a content-type");

                throw _exceptionFactory.internalServerException(ErrorCode.EXTERNAL_SERVICE_ERROR);
            }

            return contentType.toLowerCase(Locale.ROOT);
        }
        catch (MultipleHeadersException e)
        {
            _logger.warn("Entrust returned multiple Content-Type headers");

            throw _exceptionFactory.internalServerException(ErrorCode.EXTERNAL_SERVICE_ERROR);
        }
    }

    private static Map<String, String> getContextAttributes(Map<String, ?> idTokenJson)
    {
        return Map.of("upstream_acr", idTokenJson.get("acr").toString());
    }

    private Map<String, Object> redeemCodeForTokens(CallbackRequestModel requestModel)
    {
        HttpRequest.Builder request = getWebServiceClient()
                .withPath("/token")
                .request()
                .contentType("application/x-www-form-urlencoded")
                .body(getFormEncodedBodyFrom(requestModel));

        if (!_isFormPost)
        {
            byte[] headerValue = (_config.getClientId() + ":" + _config.getClientSecret()).getBytes(UTF_8);

            request.header("Authorization", "Basic " + Base64.getEncoder().encodeToString(headerValue));
        }

        HttpResponse tokenResponse = request
                .post()
                .response();

        throwIfServerError(tokenResponse, "Got error response from token endpoint");

        return _json.fromJson(tokenResponse.body(HttpResponse.asString()));
    }

    private void throwIfServerError(HttpResponse response, String message)
    {
        int statusCode = response.statusCode();

        if (statusCode != 200)
        {
            if (_logger.isWarnEnabled())
            {
                _logger.warn("{}}: error = {}, {}", message, statusCode, response.body(HttpResponse.asString()));
            }

            throw _exceptionFactory.internalServerException(ErrorCode.EXTERNAL_SERVICE_ERROR);
        }
    }

    private HttpRequest.BodyProcessor getFormEncodedBodyFrom(CallbackRequestModel requestModel)
    {
        Map<String, String> postData = createPostData(requestModel.getCode(), createRedirectUri(_config));

        if (_isFormPost)
        {
            postData.put("client_id", _config.getClientId());
            postData.put("client_secret", _config.getClientSecret());
        }

        return createFormUrlEncodedBodyProcessor(postData);
    }

    private WebServiceClient getWebServiceClient()
    {
        Optional<HttpClient> httpClient = _config.getHttpClient();
        URI issuerUri = createIssuerFromEnvironmentAndName(_config);

        if (httpClient.isPresent())
        {
            return _webServiceClientFactory.create(httpClient.get(), issuerUri.getPort())
                    .withHost(issuerUri.getHost())
                    .withPath(issuerUri.getPath());
        }
        else
        {
            return _webServiceClientFactory.create(issuerUri);
        }
    }

    private void handleError(CallbackRequestModel requestModel)
    {
        if (!Objects.isNull(requestModel.getError()))
        {
            if ("access_denied".equals(requestModel.getError()))
            {
                _logger.debug("Got an error from Entrust: {} - {}", requestModel.getError(),
                              requestModel.getErrorDescription());

                throw _exceptionFactory.authenticationFailedException("Upstream error: " + requestModel.getError());
            }

            _logger.warn("Got an error from Entrust: {} - {}", requestModel.getError(), requestModel.getErrorDescription());

            throw _exceptionFactory.externalServiceException("Login with Entrust failed");
        }
    }

    private Map<String, String> createPostData(String code, String callbackUri)
    {
        Map<String, String> postData = new HashMap<>(7);
        String codeVerifier = _config.getSessionManager().get("code_verifier").getValueOfType(String.class);

        _logger.debug("Code verifier = {}", codeVerifier);

        postData.put("code", code);
        postData.put("code_verifier", codeVerifier);
        postData.put("grant_type", "authorization_code");
        postData.put("redirect_uri", callbackUri);

        return postData;
    }
}
