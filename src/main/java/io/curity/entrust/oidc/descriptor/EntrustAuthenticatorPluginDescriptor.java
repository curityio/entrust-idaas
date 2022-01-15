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
