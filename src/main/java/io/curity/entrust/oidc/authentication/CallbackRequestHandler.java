package io.curity.entrust.oidc.authentication;

import io.curity.entrust.oidc.config.EntrustAuthenticatorPluginConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.curity.identityserver.sdk.attribute.AuthenticationAttributes;
import se.curity.identityserver.sdk.attribute.ContextAttributes;
import se.curity.identityserver.sdk.attribute.SubjectAttributes;
import se.curity.identityserver.sdk.authentication.AuthenticationResult;
import se.curity.identityserver.sdk.authentication.AuthenticatorRequestHandler;
import se.curity.identityserver.sdk.errors.ErrorCode;
import se.curity.identityserver.sdk.http.HttpRequest;
import se.curity.identityserver.sdk.http.HttpResponse;
import se.curity.identityserver.sdk.service.ExceptionFactory;
import se.curity.identityserver.sdk.service.HttpClient;
import se.curity.identityserver.sdk.service.Json;
import se.curity.identityserver.sdk.service.WebServiceClient;
import se.curity.identityserver.sdk.service.WebServiceClientFactory;
import se.curity.identityserver.sdk.service.authentication.AuthenticatorInformationProvider;
import se.curity.identityserver.sdk.web.Request;
import se.curity.identityserver.sdk.web.Response;

import java.net.URI;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import static io.curity.entrust.oidc.authentication.Util.createIssuerFromEnvironmentAndName;
import static io.curity.entrust.oidc.authentication.Util.createRedirectUri;
import static io.curity.entrust.oidc.config.EntrustAuthenticatorPluginConfig.AuthenticationMethod.FORM_POST;
import static java.nio.charset.StandardCharsets.UTF_8;
import static se.curity.identityserver.sdk.http.HttpRequest.createFormUrlEncodedBodyProcessor;

public final class CallbackRequestHandler implements AuthenticatorRequestHandler<CallbackRequestModel>
{
    private final static Logger _logger = LoggerFactory.getLogger(CallbackRequestHandler.class);

    private final ExceptionFactory _exceptionFactory;
    private final EntrustAuthenticatorPluginConfig _config;
    private final Json _json;
    private final AuthenticatorInformationProvider _authenticatorInformationProvider;
    private final WebServiceClientFactory _webServiceClientFactory;
    private final boolean _isFormPost;

    public CallbackRequestHandler(EntrustAuthenticatorPluginConfig config)
    {
        _exceptionFactory = config.getExceptionFactory();
        _config = config;
        _json = config.getJson();
        _webServiceClientFactory = config.getWebServiceClientFactory();
        _authenticatorInformationProvider = config.getAuthenticatorInformationProvider();
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
        String encodedIdTokenBody = tokenResponseData.get("id_token").toString().split("\\.", 3)[1];
        String idTokenBody = new String(Base64.getDecoder().decode(encodedIdTokenBody));
        Map<String, ?> idTokenJson = _json.fromJson(idTokenBody);
        AuthenticationAttributes attributes = AuthenticationAttributes.of(
                SubjectAttributes.of(idTokenJson.get("sub").toString()),
                ContextAttributes.of(Map.of("acr", idTokenJson.get("acr").toString())));

        return Optional.of(new AuthenticationResult(attributes));
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

        int statusCode = tokenResponse.statusCode();

        if (statusCode != 200)
        {
            if (_logger.isInfoEnabled())
            {
                _logger.info("Got error response from token endpoint: error = {}, {}", statusCode,
                        tokenResponse.body(HttpResponse.asString()));
            }

            throw _exceptionFactory.internalServerException(ErrorCode.EXTERNAL_SERVICE_ERROR);
        }

        return _json.fromJson(tokenResponse.body(HttpResponse.asString()));
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
                _logger.debug("Got an error from Entrust: {} - {}", requestModel.getError(), requestModel.getErrorDescription());

                throw _exceptionFactory.redirectException(
                        _authenticatorInformationProvider.getAuthenticationBaseUri().toASCIIString());
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
