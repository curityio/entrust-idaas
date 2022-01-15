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
import io.curity.entrust.idaas.config.EntrustAuthenticatorPluginConfig.EnvironmentAndName;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;

import static io.curity.entrust.idaas.descriptor.EntrustAuthenticatorPluginDescriptor.CALLBACK;

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
