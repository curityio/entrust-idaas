package io.curity.entrust.idaas.authentication;

import io.curity.entrust.idaas.config.EntrustAuthenticatorPluginConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import se.curity.identityserver.sdk.service.authentication.AuthenticatorInformationProvider;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Optional;

import static io.curity.entrust.idaas.authentication.Util.createIssuerFromEnvironmentAndName;
import static io.curity.entrust.idaas.authentication.Util.createRedirectUri;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public final class UtilTest
{
    @Mock
    private EntrustAuthenticatorPluginConfig config;

    @Mock
    private AuthenticatorInformationProvider authenticatorInformationProvider;

    @Mock
    private EntrustAuthenticatorPluginConfig.IssuerOrEnvironmentAndName issuerOrEnvironmentAndName;

    @Mock
    private EntrustAuthenticatorPluginConfig.EnvironmentAndName environmentAndName;

    private static final String baseUrl = "https://example.com/authn/entrust1";
    private static final String issuer = "https://example.ie.trustedauth.com/api/oidc";

    @Test
    void createRedirectUriTest() throws URISyntaxException
    {
        // GIVEN
        var expectedRedirectUri = baseUrl + "/callback";
        when(authenticatorInformationProvider.getFullyQualifiedAuthenticationUri()).thenReturn(new URI(baseUrl));
        when(config.getAuthenticatorInformationProvider()).thenReturn(authenticatorInformationProvider);

        // WHEN
        var actualRedirect = createRedirectUri(config);

        // THEN
        assertEquals(expectedRedirectUri, actualRedirect);
    }

    @Test
    void createIssuerFromIssuerUrlTest()
    {
        // GIVEN
        when(issuerOrEnvironmentAndName.getIssuer()).thenReturn(Optional.of(issuer));
        when(config.getIssuerOrEnvironmentAndName()).thenReturn(issuerOrEnvironmentAndName);
        var expectedIssuer = URI.create(issuer);

        // WHEN
        var actualIssuer = createIssuerFromEnvironmentAndName(config);

        // THEN
        assertEquals(expectedIssuer, actualIssuer);
    }

    @Test
    void createIssuerFromEnvironmentAndNameTest()
    {
        // GIVEN
        when(issuerOrEnvironmentAndName.getIssuer()).thenReturn(Optional.empty());
        when(environmentAndName.getEnvironment()).thenReturn(EntrustAuthenticatorPluginConfig.Environment.GERMANY);
        when(environmentAndName.getName()).thenReturn("other");
        when(issuerOrEnvironmentAndName.getEnvironmentAndName()).thenReturn(Optional.of(environmentAndName));
        when(config.getIssuerOrEnvironmentAndName()).thenReturn(issuerOrEnvironmentAndName);
        var expectedIssuer = URI.create(issuer.replace("ie", "de").replace("example", "other"));

        // WHEN
        var actualIssuer = createIssuerFromEnvironmentAndName(config);

        // THEN
        assertEquals(expectedIssuer, actualIssuer);
    }
}