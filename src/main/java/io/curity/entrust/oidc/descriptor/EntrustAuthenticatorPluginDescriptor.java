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

package io.curity.entrust.oidc.descriptor;

import io.curity.entrust.oidc.authentication.CallbackRequestHandler;
import io.curity.entrust.oidc.authentication.EntrustAuthenticatorRequestHandler;
import io.curity.entrust.oidc.config.EntrustAuthenticatorPluginConfig;
import se.curity.identityserver.sdk.authentication.AuthenticatorRequestHandler;
import se.curity.identityserver.sdk.plugin.descriptor.AuthenticatorPluginDescriptor;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

public final class EntrustAuthenticatorPluginDescriptor implements AuthenticatorPluginDescriptor<EntrustAuthenticatorPluginConfig>
{
    public final static String CALLBACK = "callback";

    @Override
    public String getPluginImplementationType()
    {
        return "entrust";
    }

    @Override
    public Class<? extends EntrustAuthenticatorPluginConfig> getConfigurationType()
    {
        return EntrustAuthenticatorPluginConfig.class;
    }

    @Override
    public Map<String, Class<? extends AuthenticatorRequestHandler<?>>> getAuthenticationRequestHandlerTypes()
    {
        Map<String, Class<? extends AuthenticatorRequestHandler<?>>> handlers = new LinkedHashMap<>(2);
        handlers.put("index", EntrustAuthenticatorRequestHandler.class);
        handlers.put(CALLBACK, CallbackRequestHandler.class);

        return Collections.unmodifiableMap(handlers);
    }
}
