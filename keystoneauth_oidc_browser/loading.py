from keystoneauth1 import exceptions, loading
from keystoneauth1.loading._plugins.identity.v3 import OpenIDConnectAuthorizationCode

from keystoneauth_oidc_browser import plugin


class OidcAuthorizationCodeCachedLoader(OpenIDConnectAuthorizationCode):
    @property
    def plugin_class(self):
        return plugin.OidcAuthorizationCodeCached

    def get_options(self):
        options = []
        for opt in super().get_options():
            if opt.name == "code":
                opt = loading.Opt(
                    "code",
                    secret=True,
                    deprecated=[loading.Opt("authorization-code")],
                    help="OAuth 2.0 authorization code. If omitted, a browser "
                    "login is started.",
                )
            elif opt.name == "redirect-uri":
                opt = loading.Opt(
                    "redirect-uri",
                    default=plugin.REDIRECT_URI,
                    help="OpenID Connect redirect URI. Without a port, a free "
                    "port is used.",
                )
            options.append(opt)

        options.extend(
            [
                loading.Opt(
                    "authorization-endpoint",
                    help="OpenID Connect authorization endpoint. Overrides discovery.",
                ),
                loading.Opt(
                    "redirect-timeout",
                    type=int,
                    default=plugin.REDIRECT_TIMEOUT,
                    help="Seconds to wait for the browser login.",
                ),
                loading.Opt(
                    "token-cache-enabled",
                    default="true",
                    help="Cache Keystone tokens between runs.",
                ),
                loading.Opt(
                    "token-cache-dir",
                    help="Token cache directory.",
                ),
                loading.Opt(
                    "token-cache-min-ttl",
                    type=int,
                    default=plugin.TOKEN_CACHE_MIN_TTL,
                    help="Minimum remaining validity, in seconds, for reusing a "
                    "cached token.",
                ),
            ]
        )

        return options

    def load_from_options(self, **kwargs):
        for opt in self.get_options():
            if kwargs.get(opt.dest) is None and opt.default is not None:
                kwargs[opt.dest] = opt.default

        if not kwargs.get("discovery_endpoint") and not (
            kwargs.get("access_token_endpoint")
            and (kwargs.get("authorization_endpoint") or kwargs.get("code"))
        ):
            raise exceptions.OptionError(
                "Specify 'discovery-endpoint', or 'access-token-endpoint' "
                "together with 'authorization-endpoint' (or 'code')."
            )
        return super().load_from_options(**kwargs)
