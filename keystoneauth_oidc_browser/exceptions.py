from keystoneauth1.exceptions import auth_plugins


class OidcAuthorizationEndpointNotFound(auth_plugins.AuthPluginException):
    message = (
        "OpenID Connect authorization endpoint not provided and not found in "
        "the discovery document"
    )


class OidcCallbackError(auth_plugins.AuthPluginException):
    message = "The OpenID Connect browser login failed"
