Entrust IDaaS Authenticator Plug-in
===================================

This project provides an open source Entrust IDaaS authenticator plug-in for the Curity Identity Server. This allows an administrator to add functionality to Curity which will then enable end users to login using their Entrust credentials.

System Requirements
~~~~~~~~~~~~~~~~~~~

* Curity Identity Server 5.0.0 and `its system requirements <https://developer.curity.io/docs/latest/system-admin-guide/system-requirements.html>`_
* The Entrust logo will only be shown in the Curity admin UI for instances of this authenticator if using version 6.7.3 or newer.

Requirements for Building from Source
"""""""""""""""""""""""""""""""""""""

* Maven 3
* OpenJDK 11

Compiling the Plug-in from Source
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The source is very easy to compile. To do so from a shell, issue this command: ``mvn package``. The resulting JAR file will be located in the ``target`` directory and be named ``entrust-idaas-*.jar``.

Installation
~~~~~~~~~~~~

To install this plug-in, either download a binary version available from the `releases section of this project's GitHub repository <https://github.com/curityio/entrust-idaas-authenticator/releases>`_ or compile it from source (as described above). If you compiled the plug-in from source, the package will be placed in the ``target`` subdirectory. The resulting JAR file or the one downloaded from GitHub needs to placed in the directory ``${IDSVR_HOME}/usr/share/plugins/entrust-idaas`` of each node. (The name of the last directory, ``entrust-idaas``, which is the plug-in group, is arbitrary and can be anything.) After doing so, the plug-in will become available as soon as the node is restarted.

    📝 **Note**
    
    The JAR file needs to be deployed to each run-time node and the admin node. For simple test deployments where the admin node is a run-time node, the JAR file only needs to be copied to one location.


For a more detailed explanation of installing plug-ins, refer to the `Curity developer guide <https://developer.curity.io/docs/latest/developer-guide/plugins/index.html#plugin-installation>`_.

Creating an App in Entrust
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

As `described in the Entrust documentation <https://developer.entrust-oidc.com/docs/oauth2>`_, you can `create apps <https://www.entrust-oidc.com/developer/apps>`_ that use the Entrust APIs as shown in the following figure:

    .. figure:: docs/images/create-entrust-oidc-app.png
        :name: doc-new-entrust-oidc-app
        :align: center
        :width: 500px



    .. figure:: docs/images/create-entrust-oidc-app1.png
        :name: new-entrust-oidc-app
        :align: center
        :width: 500px

    Fill in all the required information as shown in above image.

When you view the app's configuration after creating it, you'll find the ``Client ID`` and ``Client Secret``. These will be needed later when configuring the plug-in in Curity.

Entrust will also display the ``Authorized Redirect URLs`` in the new app's configuration. One of these need to match the yet-to-be-created Entrust authenticator instance in Curity. The default will not work, and, if used, will result in an error. This should be updated to some URL that follows the pattern ``$baseUrl/$authenticationEndpointPath/$entrust-oidcAuthnticatorId/callback``, where each of these URI components has the following meaning:

============================== ============================================================================================
URI Component                  Meaning
------------------------------ --------------------------------------------------------------------------------------------
``baseUrl``                    The base URL of the server (defined on the ``System --> General`` page of the
                               admin GUI). If this value is not set, then the server scheme, name, and port should be
                               used (e.g., ``https://localhost:8443``).
``authenticationEndpointPath`` The path of the authentication endpoint. In the admin GUI, this is located in the
                               authentication profile's ``Endpoints`` tab for the endpoint that has the type
                               ``auth-authentication``.
``entrust-oidcAuthenticatorId``    This is the name given to the Entrust authenticator when defining it (e.g., ``entrust-oidc1``).
============================== ============================================================================================

    .. figure:: docs/images/create-entrust-oidc-app2.png
        :align: center
        :width: 500px

    It could be helpful to also enable additional scopes. Scopes are the Entrust-related rights or permissions that the app is requesting. If the final application (not Curity, but the downstream app) is going to perform actions using the Entrust API, additional scopes probably should be enabled. Refer to the `Entrust documentation on scopes <https://developer.atlassian.com/cloud/entrust-oidc/entrust-oidc-cloud-rest-api-scopes>`_ for an explanation of those that can be enabled and what they allow.

.. warning::

    If the app configuration in Entrust does not allow a certain scope (e.g., the ``Read Email Address`` scope) but that scope is enabled in the authenticator in Curity, a server error will result. For this reason, it is important to align these two configurations or not to define any when configuring the plug-in in Curity.

Creating an Entrust IDaaS Authenticator in Curity
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The easiest way to configure a new Entrust authenticator is using the Curity admin UI. The configuration for this can be downloaded as XML or CLI commands later, so only the steps to do this in the GUI will be described.

1. Go to the ``Authenticators`` page of the authentication profile wherein the authenticator instance should be created.
2. Click the ``New Authenticator`` button.
3. Enter a name (e.g., ``entrust1``). This name needs to match the URI component in the callback URI set in the Entrust app.
4. For the type, pick the ``Entrust`` option and click ``Next``.
5. On the next page, you can define all of the standard authenticator configuration options like any previous authenticator that should run, the resulting ACR, transformers that should executed, etc. 

.. figure:: docs/images/entrust-idaas-authenticator-type-in-curity.png
    :align: center
    :width: 600px

    At the top of the configuration page, the Entrust-IDaaS-specific options can be found.

        📝 **Note**
        The Entrust-IDaaS-specific configuration is generated dynamically based on the `configuration model defined in the Java interface <https://github.com/curityio/entrust-oidc-authenticator/blob/master/src/main/java/io/curity/identityserver/plugin/entrust-idaas/config/EntrustAuthenticatorPluginConfig.java>`_.

6. In the ``Client ID`` text field, enter the ``Client ID`` from the Entrust IDaaS client application.
7. Also enter the matching ``Client Secret``.
8. If you wish to request additional scopes from Entrust IDaaS, enter each one in the ``Additional Scopes`` multi-select widget (e.g., ``address`` or ``profile``).
9. The ``Authentication Method`` should match the configuration for the client in Entrust IDaaS. The default is ``basic`` authentication.
10. If ``Relay Prompt`` is configured and an OAuth client sends a ``prompt`` to the Curity OAuth server, then this parameter will be forwarded upstream to Entrust IDaaS.
11. In the ``Issuer or Environment and Name`` dropdown select and configure one of the following:

    A. ``environment-and-name`` can be selected and one of the environments where your Entrust IDaaS is hosted should be selected. In this case, the instance name also has to be configured.
    B. ``issuer`` can be selected and the Entrust IDaaS OpenID Connect issuer URL can be configured.
12. Once all of these changes are made, they will be staged, but not committed (i.e., not running). To make them active, click the ``Commit`` menu option in the ``Changes`` menu. Optionally, enter a comment in the ``Deploy Changes`` dialogue and click ``OK``.

Once the configuration is committed and running, the authenticator can be used like any other.

    📝 **Note**
    If you need to contact the Entrust IDaaS web services via a proxy, then you should also configure the optional HTTP client. This can be done by `following the as described in the reference manual <https://curity.io/docs/idsvr/latest/system-admin-guide/http-clients/index.html>`_

Passing Along the ACR
"""""""""""""""""""""

To pass the Entrust IDaaS ACR down through Curity to an OAuth client, a token procedure has to be added because authenticators like the Entrust one cannot change the ACR (by design). In cases where the use of the Entrust ACR is desirable, do the following:

1. Go to the ``Endpoints`` page of the applicable token service profile.
2. Select a token endpoint and expand the flows.
3. In the ``Authorization Code`` dropdown, click ``New procedure``. Give it a name (e.g., ``change_acr``) and click ``Save``.
4. In the procedure that opens, modify the condition that checks ID token data. This will be on or around line 21

.. code:: javascript

    if (idTokenData) {
        var idTokenIssuer = context.idTokenIssuer;
        
        // START ADD
        var upstreamAcr = context.contextAttributes().upstream_acr;
        
        if (upstreamAcr) {
            idTokenData.acr = idTokenData.amr = upstreamAcr;
        }
        // END ADD
        
        idTokenData.at_hash = idTokenIssuer.atHash(issuedAccessToken);

        responseData.id_token = idTokenIssuer.issue(idTokenData, issuedDelegation);
    }

License
~~~~~~~

This plugin and its associated documentation is listed under the `Apache 2 license <LICENSE>`_.

More Information
~~~~~~~~~~~~~~~~

Please visit `curity.io <https://curity.io/>`_ for more information about the Curity Identity Server.

Copyright (C) 2022 Curity AB.
