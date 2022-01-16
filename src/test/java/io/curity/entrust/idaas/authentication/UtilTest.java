package io.curity.entrust.idaas.authentication;

import io.curity.entrust.idaas.config.EntrustAuthenticatorPluginConfig;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import se.curity.identityserver.sdk.service.authentication.AuthenticatorInformationProvider;

import java.net.URI;
import java.net.URISyntaxException;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public final class UtilTest
{
    @Test
    void createRedirectUri() throws URISyntaxException
    {
        // GIVEN
        var baseUrl = "https://example.com/authn/entrust1";
        var expectedRedirectUri = baseUrl + "/callback";
        var configMock = mock(EntrustAuthenticatorPluginConfig.class);
        var authenticatorInfoMock = mock(AuthenticatorInformationProvider.class);
        when(authenticatorInfoMock.getFullyQualifiedAuthenticationUri()).thenReturn(new URI(baseUrl));
        when(configMock.getAuthenticatorInformationProvider()).thenReturn(authenticatorInfoMock);

        // WHEN
        var actualRedirect = Util.createRedirectUri(configMock);

        // THEN
        Assertions.assertEquals(expectedRedirectUri, actualRedirect);
    }
}