import base64
import datetime
import hashlib
import json
import os
import socket
import threading
import urllib.request
from urllib.parse import parse_qs, urlencode, urlparse

import pytest
from keystoneauth1 import exceptions as ks_exceptions
from keystoneauth1 import fixture, loading, session

from keystoneauth_oidc_browser import browser, exceptions
from keystoneauth_oidc_browser.loading import OidcAuthorizationCodeCachedLoader
from keystoneauth_oidc_browser.plugin import OidcAuthorizationCodeCached

AUTH_URL = "https://keystone.example.com/v3"
OTHER_AUTH_URL = "https://keystone2.example.com/v3"
DISCOVERY_URL = "https://idp.example.com/.well-known/openid-configuration"
TOKEN_ENDPOINT = "https://idp.example.com/token"
FEDERATED_URL = AUTH_URL + "/OS-FEDERATION/identity_providers/idp/protocols/openid/auth"
RESCOPE_URL = AUTH_URL + "/auth/tokens"

UNSCOPED_TOKEN = "unscoped-token"
SCOPED_TOKEN = "scoped-token"


def _expires(seconds):
    now = datetime.datetime.now(datetime.timezone.utc)
    when = now + datetime.timedelta(seconds=seconds)
    return when.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class Keystone:
    """Fake identity provider and Keystone, counting the calls they get."""

    def __init__(self, requests_mock, ttl=3600, auth_url=AUTH_URL):
        self.mock = requests_mock
        self.auth_url = auth_url
        self.discovery = requests_mock.get(
            DISCOVERY_URL,
            json={
                "token_endpoint": TOKEN_ENDPOINT,
                "authorization_endpoint": "https://idp.example.com/auth",
                "grant_types_supported": ["authorization_code"],
            },
        )
        self.idp_token = requests_mock.post(
            TOKEN_ENDPOINT, json={"access_token": "oidc-access-token"}
        )
        self.federated = requests_mock.post(
            auth_url + "/OS-FEDERATION/identity_providers/idp/protocols/openid/auth",
            json=fixture.V3Token(expires=_expires(ttl)),
            headers={"X-Subject-Token": UNSCOPED_TOKEN},
        )
        self.set_rescope(ttl)

    def set_rescope(self, ttl=3600, status=201):
        body = fixture.V3Token(
            expires=_expires(ttl), project_id="p-id", project_name="proj"
        )
        self.rescope = self.mock.post(
            self.auth_url + "/auth/tokens",
            status_code=status,
            json=body if status < 400 else {"error": {"code": status}},
            headers={"X-Subject-Token": SCOPED_TOKEN},
        )


@pytest.fixture
def keystone(requests_mock):
    return Keystone(requests_mock)


@pytest.fixture
def cache_dir(tmp_path):
    return str(tmp_path / "cache")


@pytest.fixture
def redirect_uri():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    return "http://127.0.0.1:%d" % port


class FakeBrowser:
    """Stands in for the user: follows the login URL back to the callback."""

    def __init__(self):
        self.queries = []

    def open(self, url, **kwargs):
        query = {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}
        self.queries.append(query)
        target = "%s?%s" % (
            query["redirect_uri"],
            urlencode({"code": "browser-code", "state": query["state"]}),
        )

        def redirect():
            try:
                urllib.request.urlopen(target, timeout=5).read()
            except OSError:
                pass

        threading.Thread(target=redirect, daemon=True).start()
        return True


@pytest.fixture
def fake_browser(monkeypatch):
    fake = FakeBrowser()
    monkeypatch.setattr(browser.webbrowser, "open", fake.open)
    return fake


def make_plugin(cache_dir, code="the-code", **kwargs):
    params = {
        "auth_url": AUTH_URL,
        "identity_provider": "idp",
        "protocol": "openid",
        "client_id": "client",
        "client_secret": "secret",
        "discovery_endpoint": DISCOVERY_URL,
        "code": code,
        "project_name": "proj",
        "project_domain_name": "Default",
        "token_cache_dir": cache_dir,
    }
    params.update(kwargs)
    return OidcAuthorizationCodeCached(**params)


def authenticate(plugin):
    return plugin.get_access(session.Session())


def test_first_run_caches_both_tokens(keystone, cache_dir):
    auth_ref = authenticate(make_plugin(cache_dir))

    assert auth_ref.auth_token == SCOPED_TOKEN
    assert keystone.idp_token.call_count == 1
    assert keystone.rescope.call_count == 1
    files = os.listdir(cache_dir)
    assert len(files) == 2
    for name in files:
        assert os.stat(os.path.join(cache_dir, name)).st_mode & 0o777 == 0o600


def test_second_run_needs_no_code_and_no_requests(keystone, cache_dir):
    authenticate(make_plugin(cache_dir))
    keystone.mock.reset_mock()

    auth_ref = authenticate(make_plugin(cache_dir, code=None))

    assert auth_ref.auth_token == SCOPED_TOKEN
    assert auth_ref.project_id == "p-id"
    assert keystone.mock.call_count == 0


def test_other_project_rescopes_the_cached_unscoped_token(keystone, cache_dir):
    authenticate(make_plugin(cache_dir))
    keystone.mock.reset_mock()

    auth_ref = authenticate(make_plugin(cache_dir, code=None, project_name="other"))

    assert auth_ref.auth_token == SCOPED_TOKEN
    assert keystone.idp_token.call_count == 0
    assert keystone.federated.call_count == 0
    assert keystone.rescope.call_count == 1
    sent = keystone.rescope.last_request.json()["auth"]
    assert sent["identity"]["token"]["id"] == UNSCOPED_TOKEN
    assert sent["scope"]["project"]["name"] == "other"


def test_switching_projects_back_and_forth_uses_cache(keystone, cache_dir):
    authenticate(make_plugin(cache_dir))
    authenticate(make_plugin(cache_dir, code=None, project_name="other"))
    assert keystone.idp_token.call_count == 1
    assert keystone.federated.call_count == 1
    assert keystone.rescope.call_count == 2
    keystone.mock.reset_mock()

    authenticate(make_plugin(cache_dir, code=None))
    authenticate(make_plugin(cache_dir, code=None, project_name="other"))

    assert keystone.mock.call_count == 0
    assert len(os.listdir(cache_dir)) == 3


def test_other_cloud_on_the_same_idp_does_not_reuse_tokens(
    requests_mock, cache_dir, fake_browser
):
    Keystone(requests_mock)
    other = Keystone(requests_mock, auth_url=OTHER_AUTH_URL)
    authenticate(make_plugin(cache_dir))
    requests_mock.reset_mock()

    authenticate(make_plugin(cache_dir, code=None, auth_url=OTHER_AUTH_URL))

    assert len(fake_browser.queries) == 1
    assert other.federated.call_count == 1
    assert len(os.listdir(cache_dir)) == 4


def test_auth_url_trailing_slash_shares_the_cache(cache_dir):
    base = make_plugin(cache_dir)
    slash = make_plugin(cache_dir, auth_url=AUTH_URL + "/")
    assert slash._scoped_key() == base._scoped_key()
    assert slash._unscoped_key() == base._unscoped_key()


def test_nearly_expired_tokens_are_not_reused(requests_mock, cache_dir):
    keystone = Keystone(requests_mock, ttl=200)
    authenticate(make_plugin(cache_dir))
    keystone.mock.reset_mock()

    authenticate(make_plugin(cache_dir, code="fresh", token_cache_min_ttl=300))
    assert keystone.idp_token.call_count == 1
    keystone.mock.reset_mock()

    authenticate(make_plugin(cache_dir, code=None, token_cache_min_ttl=100))
    assert keystone.mock.call_count == 0


def test_browser_login_public_client_on_a_free_port(keystone, cache_dir, fake_browser):
    plugin = make_plugin(cache_dir, code=None, client_secret=None)
    assert plugin.redirect_uri == "http://127.0.0.1"

    auth_ref = authenticate(plugin)

    assert auth_ref.auth_token == SCOPED_TOKEN
    (query,) = fake_browser.queries
    sent_uri = urlparse(query["redirect_uri"])
    assert sent_uri.hostname == "127.0.0.1"
    assert sent_uri.port
    assert query["client_id"] == "client"
    assert query["response_type"] == "code"
    assert query["code_challenge_method"] == "S256"

    request = keystone.idp_token.last_request
    sent = {k: v[0] for k, v in parse_qs(request.text).items()}
    assert sent["code"] == "browser-code"
    assert sent["grant_type"] == "authorization_code"
    assert sent["redirect_uri"] == query["redirect_uri"]
    assert sent["client_id"] == "client"
    digest = hashlib.sha256(sent["code_verifier"].encode()).digest()
    assert (
        base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        == query["code_challenge"]
    )
    assert "Authorization" not in request.headers
    # The picked port is not kept on the plugin.
    assert plugin.redirect_uri == "http://127.0.0.1"


def test_free_port_keeps_the_redirect_path(keystone, cache_dir, fake_browser):
    authenticate(make_plugin(cache_dir, code=None, redirect_uri="http://127.0.0.1/cb"))

    sent_uri = urlparse(fake_browser.queries[0]["redirect_uri"])
    assert sent_uri.port and sent_uri.path == "/cb"


def test_explicit_redirect_port_is_used(
    keystone, cache_dir, fake_browser, redirect_uri
):
    authenticate(make_plugin(cache_dir, code=None, redirect_uri=redirect_uri))
    assert fake_browser.queries[0]["redirect_uri"] == redirect_uri
    sent = parse_qs(keystone.idp_token.last_request.text)
    assert sent["redirect_uri"] == [redirect_uri]


def test_browser_login_confidential_client(keystone, cache_dir, fake_browser):
    authenticate(make_plugin(cache_dir, code=None))

    request = keystone.idp_token.last_request
    assert request.headers["Authorization"].startswith("Basic ")
    assert "code_verifier" in parse_qs(request.text)


def test_browser_login_happens_once_then_cache(keystone, cache_dir, fake_browser):
    authenticate(make_plugin(cache_dir, code=None))
    authenticate(make_plugin(cache_dir, code=None))
    authenticate(make_plugin(cache_dir, code=None, project_name="x"))

    assert len(fake_browser.queries) == 1
    assert keystone.idp_token.call_count == 1


def test_browser_login_timeout(keystone, cache_dir, monkeypatch):
    monkeypatch.setattr(browser.webbrowser, "open", lambda url, **kw: True)

    with pytest.raises(exceptions.OidcCallbackError):
        authenticate(make_plugin(cache_dir, code=None, redirect_timeout=1))
    assert keystone.idp_token.call_count == 0


def test_authorization_endpoint_option_skips_discovery(
    keystone, cache_dir, fake_browser
):
    authenticate(
        make_plugin(
            cache_dir,
            code=None,
            discovery_endpoint=None,
            access_token_endpoint=TOKEN_ENDPOINT,
            authorization_endpoint="https://idp.example.com/other-auth",
        )
    )
    assert keystone.discovery.call_count == 0
    assert keystone.idp_token.call_count == 1


def test_refused_unscoped_token_is_replaced(keystone, cache_dir):
    authenticate(make_plugin(cache_dir))
    keystone.mock.reset_mock()

    # The scoped token is not cached for this project; the cached unscoped
    # token has been revoked, so the first rescope fails.
    good = fixture.V3Token(expires=_expires(3600), project_name="other")
    keystone.mock.post(
        RESCOPE_URL,
        [
            {"status_code": 401, "json": {}},
            {"status_code": 201, "json": good, "headers": {"X-Subject-Token": "new"}},
        ],
    )

    auth_ref = authenticate(
        make_plugin(cache_dir, code="new-code", project_name="other")
    )

    assert auth_ref.auth_token == "new"
    assert keystone.idp_token.call_count == 1
    assert "new-code" in keystone.idp_token.last_request.text


def test_refused_unscoped_token_triggers_browser_login(
    keystone, cache_dir, fake_browser
):
    authenticate(make_plugin(cache_dir))
    keystone.mock.reset_mock()
    good = fixture.V3Token(expires=_expires(3600), project_name="other")
    keystone.mock.post(
        RESCOPE_URL,
        [
            {"status_code": 401, "json": {}},
            {"status_code": 201, "json": good, "headers": {"X-Subject-Token": "new"}},
        ],
    )

    auth_ref = authenticate(make_plugin(cache_dir, code=None, project_name="other"))

    assert auth_ref.auth_token == "new"
    assert len(fake_browser.queries) == 1


def test_rescope_refused_after_fresh_login_is_raised(keystone, cache_dir, fake_browser):
    # No access to the project: logging in again cannot help, so give up
    # after one attempt instead of looping.
    authenticate(make_plugin(cache_dir))
    keystone.set_rescope(status=401)

    with pytest.raises(ks_exceptions.Unauthorized):
        authenticate(make_plugin(cache_dir, code=None, project_name="other"))
    assert len(fake_browser.queries) == 1


def test_used_code_is_not_exchanged_again(keystone, cache_dir, fake_browser):
    plugin = make_plugin(cache_dir, code="once")
    authenticate(plugin)
    plugin.invalidate()
    keystone.mock.reset_mock()
    good = fixture.V3Token(expires=_expires(3600), project_name="proj")
    keystone.mock.post(
        RESCOPE_URL,
        [
            {"status_code": 401, "json": {}},
            {"status_code": 201, "json": good, "headers": {"X-Subject-Token": "new"}},
        ],
    )

    assert authenticate(plugin).auth_token == "new"
    assert len(fake_browser.queries) == 1
    assert "once" not in keystone.idp_token.last_request.text


def test_invalidate_drops_only_the_scoped_token(keystone, cache_dir):
    plugin = make_plugin(cache_dir)
    authenticate(plugin)

    assert plugin.invalidate()
    assert len(os.listdir(cache_dir)) == 1
    assert plugin.token_cache.get(plugin._unscoped_key()) is not None


def test_cached_unscoped_is_kept_after_invalidate(keystone, cache_dir, fake_browser):
    authenticate(make_plugin(cache_dir))
    keystone.mock.reset_mock()

    plugin = make_plugin(cache_dir, code=None, project_name="other")
    authenticate(plugin)
    plugin.invalidate()
    authenticate(plugin)

    assert fake_browser.queries == []
    assert keystone.rescope.call_count == 2


def test_service_401_rescopes_without_login(keystone, cache_dir, fake_browser):
    authenticate(make_plugin(cache_dir))
    keystone.mock.reset_mock()
    servers = keystone.mock.get(
        "https://compute.example.com/servers",
        [{"status_code": 401}, {"status_code": 200, "json": {}}],
    )

    plugin = make_plugin(cache_dir, code=None)
    session.Session(auth=plugin).get("https://compute.example.com/servers")

    assert servers.call_count == 2
    assert keystone.rescope.call_count == 1
    assert fake_browser.queries == []


def test_service_401_with_revoked_unscoped_logs_in_again(
    keystone, cache_dir, fake_browser
):
    authenticate(make_plugin(cache_dir))
    servers = keystone.mock.get(
        "https://compute.example.com/servers",
        [{"status_code": 401}, {"status_code": 200, "json": {}}],
    )
    good = fixture.V3Token(expires=_expires(3600), project_name="proj")
    keystone.mock.post(
        RESCOPE_URL,
        [
            {"status_code": 401, "json": {}},
            {"status_code": 201, "json": good, "headers": {"X-Subject-Token": "new"}},
        ],
    )

    plugin = make_plugin(cache_dir, code=None)
    session.Session(auth=plugin).get("https://compute.example.com/servers")

    assert servers.call_count == 2
    assert len(fake_browser.queries) == 1


def test_cache_can_be_disabled(keystone, cache_dir):
    authenticate(make_plugin(cache_dir, token_cache_enabled="false"))
    assert not os.path.exists(cache_dir)


def test_corrupt_cached_state_falls_back_to_login(keystone, cache_dir):
    plugin = make_plugin(cache_dir)
    authenticate(plugin)
    for key in (plugin._scoped_key(), plugin._unscoped_key()):
        plugin.token_cache.set(key, json.dumps({"no": "token"}), 2**31)
    keystone.mock.reset_mock()

    auth_ref = authenticate(make_plugin(cache_dir))

    assert auth_ref.auth_token == SCOPED_TOKEN
    assert keystone.idp_token.call_count == 1


def test_cache_key_ignores_code_but_not_scope_client_or_cloud(cache_dir):
    base = make_plugin(cache_dir)
    assert make_plugin(cache_dir, code="other")._scoped_key() == base._scoped_key()
    assert make_plugin(cache_dir, project_name="x")._scoped_key() != base._scoped_key()
    assert (
        make_plugin(cache_dir, project_name="x")._unscoped_key() == base._unscoped_key()
    )
    assert make_plugin(cache_dir, client_id="x")._unscoped_key() != base._unscoped_key()
    other = make_plugin(cache_dir, auth_url=OTHER_AUTH_URL)
    assert other._unscoped_key() != base._unscoped_key()
    assert other._scoped_key() != base._scoped_key()
    assert base.get_cache_id() is not None


def test_loader_is_registered_and_code_is_optional(cache_dir):
    loader = loading.get_plugin_loader("v3oidcbrowser")
    assert isinstance(loader, OidcAuthorizationCodeCachedLoader)

    options = {o.dest: o for o in loader.get_options()}
    assert not options["code"].required
    assert options["code"].secret
    assert {
        "token_cache_enabled",
        "token_cache_dir",
        "token_cache_min_ttl",
        "authorization_endpoint",
        "redirect_timeout",
    } <= set(options)

    plugin = loader.load_from_options(
        auth_url=AUTH_URL,
        identity_provider="idp",
        protocol="openid",
        client_id="client",
        client_secret="secret",
        discovery_endpoint=DISCOVERY_URL,
        token_cache_dir=cache_dir,
        token_cache_min_ttl="60",
        token_cache_enabled="yes",
    )
    assert isinstance(plugin, OidcAuthorizationCodeCached)
    assert plugin.token_cache_min_ttl == 60
    assert plugin.token_cache is not None


def test_loader_with_partial_options_like_openrc():
    # osc-lib passes only what is set.
    loader = loading.get_plugin_loader("v3oidcbrowser")
    plugin = loader.load_from_options(
        auth_url=AUTH_URL,
        identity_provider="openstack",
        protocol="openid",
        client_id="public-client",
        discovery_endpoint=DISCOVERY_URL,
        project_id="p-id",
    )
    assert plugin.project_id == "p-id"
    assert plugin.client_secret is None
    assert plugin.redirect_uri == "http://127.0.0.1"


def test_loader_has_no_idp_defaults():
    loader = loading.get_plugin_loader("v3oidcbrowser")
    options = {o.dest: o for o in loader.get_options()}
    assert options["identity_provider"].required
    assert options["protocol"].required
    assert options["discovery_endpoint"].default is None
    with pytest.raises(ks_exceptions.OptionError):
        loader.load_from_options(auth_url=AUTH_URL, project_id="p-id")


def test_loader_needs_a_way_to_reach_the_idp():
    loader = loading.get_plugin_loader("v3oidcbrowser")
    with pytest.raises(ks_exceptions.OptionError):
        loader.load_from_options(
            auth_url=AUTH_URL,
            identity_provider="idp",
            protocol="openid",
            client_id="client",
            access_token_endpoint=TOKEN_ENDPOINT,
        )


def test_option_help_is_argparse_safe():
    # argparse %-formats help strings; a stray "%" breaks "openstack --help".
    import argparse

    parser = argparse.ArgumentParser()
    for opt in loading.get_plugin_loader("v3oidcbrowser").get_options():
        parser.add_argument("--os-" + opt.name, help=opt.help)
    parser.format_help()


def test_registers_one_name_that_nobody_else_uses():
    from importlib.metadata import distributions

    # Sets: the same dist can be listed twice when an egg-info from an
    # editable build sits on sys.path next to the installed metadata.
    owners = {}
    ours = set()
    for dist in distributions():
        for ep in dist.entry_points:
            if ep.group != "keystoneauth1.plugin":
                continue
            owners.setdefault(ep.name, set()).add(dist.metadata["Name"])
            if ep.value.startswith("keystoneauth_oidc_browser."):
                ours.add(ep.name)

    assert ours == {"v3oidcbrowser"}
    assert owners["v3oidcbrowser"] == {"keystoneauth-oidc-browser"}
