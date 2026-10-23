"""Upstream ``v3oidcauthcode`` with a browser login and tokens kept between runs.

When nothing usable is cached the user logs in through the browser (with
PKCE), unless an authorization code was passed in, as upstream expects.

Two tokens are cached, both per cloud (``auth_url``), so several OpenStack
clouds behind one identity provider never see each other's tokens:

* the federated **unscoped** token, keyed without any scope, so it can be
  rescoped to any project without going back to the identity provider;
* the **scoped** token, keyed with the scope, so a repeated command only asks
  Keystone, once, whether the cached token is still valid.

A cached token that Keystone reports revoked (``openstack token revoke``), or
a ``401`` from any service, drops both tokens: the next login goes through the
browser again.
"""

from __future__ import annotations

import hashlib
import json
import logging
import secrets
from urllib.parse import urlencode, urlparse

from keystoneauth1 import access
from keystoneauth1 import exceptions as ks_exceptions
from keystoneauth1.identity.v3.oidc import OidcAuthorizationCode

from keystoneauth_oidc_browser import browser, exceptions
from keystoneauth_oidc_browser.token_cache import FileTokenCache

LOG = logging.getLogger(__name__)

REDIRECT_URI = "http://127.0.0.1"
REDIRECT_TIMEOUT = 120
TOKEN_CACHE_MIN_TTL = 300

_SCOPE_ATTRS = (
    "trust_id",
    "system_scope",
    "domain_id",
    "domain_name",
    "project_id",
    "project_name",
    "project_domain_id",
    "project_domain_name",
)

_FALSE_STRINGS = frozenset(("0", "false", "no", "off", "n", "f"))


def _to_bool(value) -> bool:
    if isinstance(value, str):
        return value.strip().lower() not in _FALSE_STRINGS
    return bool(value)


class OidcAuthorizationCodeCached(OidcAuthorizationCode):
    """OpenID Connect Authorization Code with a persistent token cache.

    Accepts every argument of
    :py:class:`keystoneauth1.identity.v3.oidc.OidcAuthorizationCode`, with
    ``client_secret`` optional (public clients rely on PKCE), plus:

    :param authorization_endpoint: the identity provider's authorization
        endpoint, taken from the discovery document when not given.
    :param redirect_timeout: seconds to wait for the browser login.
    :param token_cache_enabled: whether to use the cache at all.
    :param token_cache_dir: where to keep tokens, the platform's per-user
        cache directory when not given.
    :param token_cache_min_ttl: seconds a cached token must still be valid
        for to be reused.
    """

    def __init__(
        self,
        *args,
        token_cache_enabled=True,
        token_cache_dir: str | None = None,
        token_cache_min_ttl=TOKEN_CACHE_MIN_TTL,
        authorization_endpoint: str | None = None,
        redirect_timeout=REDIRECT_TIMEOUT,
        **kwargs,
    ):
        if len(args) < 5:
            kwargs.setdefault("client_secret", None)
        super().__init__(*args, **kwargs)
        self.redirect_uri = self.redirect_uri or REDIRECT_URI
        self.authorization_endpoint = authorization_endpoint
        self.redirect_timeout = int(
            REDIRECT_TIMEOUT if redirect_timeout is None else redirect_timeout
        )
        self.token_cache_min_ttl = int(
            TOKEN_CACHE_MIN_TTL if token_cache_min_ttl is None else token_cache_min_ttl
        )
        self.token_cache = (
            FileTokenCache(token_cache_dir)
            if _to_bool(True if token_cache_enabled is None else token_cache_enabled)
            else None
        )
        self._served_cached_unscoped = False

    def _unscoped_elements(self) -> dict[str, str | None]:
        return {
            "auth_url": self.auth_url.rstrip("/"),
            "oidc_identity_provider": self.identity_provider,
            "oidc_protocol": self.protocol,
            "oidc_client_id": self.client_id,
            "oidc_client_secret": self.client_secret,
            "oidc_scope": self.scope,
            "oidc_access_token_type": self.access_token_type,
        }

    def get_cache_id_elements(self) -> dict[str, str | None]:
        """Identify the scoped token, for any caller of ``get_cache_id``.

        This also lets openstacksdk's keyring cache (``cache: {auth: true}``
        in clouds.yaml) store tokens from this plugin.
        """
        elements = self._unscoped_elements()
        for attr in _SCOPE_ATTRS:
            elements[attr] = getattr(self, attr)
        return elements

    @staticmethod
    def _key(kind: str, elements: dict[str, str | None]) -> str:
        hasher = hashlib.sha256()
        hasher.update(kind.encode("utf-8") + b"\x00")
        for name, value in sorted(elements.items()):
            if value is None:
                continue
            hasher.update(name.encode("utf-8") + b"\x00")
            hasher.update(str(value).encode("utf-8") + b"\x00")
        return hasher.hexdigest()

    def _scoped_key(self) -> str:
        return self._key("scoped", self.get_cache_id_elements())

    def _unscoped_key(self) -> str:
        return self._key("unscoped", self._unscoped_elements())

    def _load(self, key: str) -> access.AccessInfoV3 | None:
        if self.token_cache is None:
            return None

        state = self.token_cache.get(key)
        if state is None:
            return None

        try:
            data = json.loads(state)
            auth_ref = access.create(body=data["body"], auth_token=data["auth_token"])
        except (ValueError, KeyError, TypeError) as e:
            LOG.debug("Discarding malformed cached token: %s", e)
            self.token_cache.delete(key)
            return None

        if not isinstance(auth_ref, access.AccessInfoV3):
            self.token_cache.delete(key)
            return None

        if auth_ref.will_expire_soon(self.token_cache_min_ttl):
            return None

        return auth_ref

    def _store(self, key: str, auth_ref: access.AccessInfo) -> None:
        if self.token_cache is None or auth_ref.expires is None:
            return
        state = json.dumps({"auth_token": auth_ref.auth_token, "body": auth_ref._data})
        self.token_cache.set(
            key, state, auth_ref.expires.timestamp(), group=self._unscoped_key()
        )

    def _forget(self, key: str) -> None:
        if self.token_cache is not None:
            self.token_cache.delete(key)

    def _logout(self) -> None:
        """Drop every cached token of this login, whatever its scope."""
        self._forget(self._scoped_key())
        self._forget(self._unscoped_key())
        if self.token_cache is not None:
            self.token_cache.delete_group(self._unscoped_key())

    def _is_revoked(self, session, auth_ref: access.AccessInfoV3) -> bool:
        """Ask Keystone whether a token read from the cache was revoked.

        Anything but a clear "no such token" counts as valid: a broken cache
        check must never stand in the way of authenticating.
        """
        token = auth_ref.auth_token
        try:
            resp = session.request(
                self.auth_url.rstrip("/") + "/auth/tokens",
                "HEAD",
                authenticated=False,
                raise_exc=False,
                headers={"X-Auth-Token": token, "X-Subject-Token": token},
            )
        except ks_exceptions.ClientException as e:
            LOG.debug("Could not validate the cached token: %s", e)
            return False
        return resp.status_code in (401, 404)

    def _get_authorization_endpoint(self, session) -> str:
        if self.authorization_endpoint:
            return self.authorization_endpoint
        endpoint = self._get_discovery_document(session).get("authorization_endpoint")
        if not endpoint or not isinstance(endpoint, str):
            raise exceptions.OidcAuthorizationEndpointNotFound()
        return endpoint

    def get_payload(self, session):
        if self.code:
            payload = super().get_payload(session)
            self.code = None
            return payload

        redirect = urlparse(self.redirect_uri)
        server = browser.bind_callback_server(
            redirect.hostname or "127.0.0.1", redirect.port or 0
        )
        if redirect.port:
            redirect_uri = self.redirect_uri
        else:
            port = server.server_address[1]
            redirect_uri = redirect._replace(
                netloc="%s:%d" % (redirect.netloc, port)
            ).geturl()

        verifier, challenge = browser.make_pkce_pair()
        state = secrets.token_urlsafe(32)
        query = {
            "client_id": self.client_id,
            "response_type": "code",
            "scope": self.scope,
            "redirect_uri": redirect_uri,
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        try:
            url = "%s?%s" % (
                self._get_authorization_endpoint(session),
                urlencode(query),
            )
            browser.open_browser(url)
        except Exception:
            server.server_close()
            raise

        code = browser.wait_for_code(server, state, self.redirect_timeout)

        return {
            "redirect_uri": redirect_uri,
            "code": code,
            "code_verifier": verifier,
        }

    def get_unscoped_auth_ref(self, session, **kwargs):
        key = self._unscoped_key()

        if self._served_cached_unscoped:
            self._served_cached_unscoped = False
            self._forget(key)
        else:
            auth_ref = self._load(key)
            if auth_ref is not None:
                LOG.debug("Using the cached unscoped token")
                self._served_cached_unscoped = True
                return auth_ref

        auth_ref = super().get_unscoped_auth_ref(session)
        self._store(key, auth_ref)
        return auth_ref

    def get_auth_ref(self, session, **kwargs):
        key = self._scoped_key()

        auth_ref = self._load(key)
        if auth_ref is not None:
            if not self._is_revoked(session, auth_ref):
                LOG.debug("Using the cached token")
                return auth_ref
            LOG.debug("The cached token was revoked, logging in again")
            self._logout()

        try:
            try:
                auth_ref = super().get_auth_ref(session)
            except ks_exceptions.Unauthorized:
                if not self._served_cached_unscoped:
                    raise
                LOG.debug("The cached unscoped token was refused, authenticating again")
                self._unscoped_auth_ref = None
                auth_ref = super().get_auth_ref(session)
        finally:
            self._served_cached_unscoped = False

        self._store(key, auth_ref)
        return auth_ref

    def invalidate(self):
        self._logout()
        return super().invalidate()
