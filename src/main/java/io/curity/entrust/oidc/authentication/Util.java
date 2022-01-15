package io.curity.entrust.oidc.authentication;

import io.curity.entrust.oidc.config.EntrustAuthenticatorPluginConfig;
import io.curity.entrust.oidc.config.EntrustAuthenticatorPluginConfig.EnvironmentAndName;
import se.curity.identityserver.sdk.errors.ErrorCode;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;

import static io.curity.entrust.oidc.descriptor.EntrustAuthenticatorPluginDescriptor.CALLBACK;

final class Util
{
    private Util()
    {
    }

    public static String createRedirectUri(EntrustAuthenticatorPluginConfig config)
    {
        try
        {
            URI authUri = config.getAuthenticatorInformationProvider().getFullyQualifiedAuthenticationUri();

            return new URL(authUri.toURL(), authUri.getPath() + "/" + CALLBACK).toString();
        }
        catch (MalformedURLException e)
        {
            throw new RuntimeException("Could not create redirect URI");
        }
    }

    public static URI createIssuerFromEnvironmentAndName(EntrustAuthenticatorPluginConfig config)
    {
        EntrustAuthenticatorPluginConfig.IssuerOrEnvironmentAndName issuerOrEnvironmentAndName =
                config.getIssuerOrEnvironmentAndName();

        return issuerOrEnvironmentAndName.getIssuer()
                .map(URI::create)
                .orElseGet(() -> createIssuerFromEnvironmentAndName(
                        issuerOrEnvironmentAndName.getEnvironmentAndName()
                                .orElseThrow(() -> new RuntimeException(
                                        "Issuer wasn't configured nor is the environment and name"))));
    }

    private static URI createIssuerFromEnvironmentAndName(EnvironmentAndName environmentAndName)
    {
        try
        {
            String environmentSlug;
            EntrustAuthenticatorPluginConfig.Environment environment = environmentAndName.getEnvironment();

            switch (environment)
            {
                case US:
                    environmentSlug = "us";
                    break;
                case IRELAND:
                    environmentSlug = "ie";
                    break;
                case GERMANY:
                    environmentSlug = "de";
                    break;
                default:
                    environmentSlug = environment.toString();
            }

            String host = environmentAndName.getName() +
                    "." +
                    environmentSlug +
                    ".trustedauth.com";

            return new URI("https",
                           host,
                           "/api/oidc",
                           null);
        }
        catch (URISyntaxException e)
        {
            throw new RuntimeException(e);
        }
    }
}
