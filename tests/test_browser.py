import base64
import hashlib
import socket
import threading
import urllib.error
import urllib.request

import pytest

from keystoneauth_oidc_browser import browser, exceptions


@pytest.fixture
def server():
    srv = browser.bind_callback_server("127.0.0.1", 0)
    yield srv
    srv.server_close()


def _get(server, *queries):
    """Send the requests one after another, as a browser would."""
    base = "http://127.0.0.1:%d/" % server.server_address[1]

    def run():
        for query in queries:
            try:
                urllib.request.urlopen(base + query, timeout=5).read()
            except (OSError, urllib.error.HTTPError):
                pass

    threading.Thread(target=run, daemon=True).start()


def test_pkce_pair():
    verifier, challenge = browser.make_pkce_pair()
    assert 43 <= len(verifier) <= 128
    digest = hashlib.sha256(verifier.encode()).digest()
    assert challenge == base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    assert browser.make_pkce_pair()[0] != verifier


def test_code_is_returned(server):
    _get(server, "?code=abc&state=s1")
    assert browser.wait_for_code(server, "s1", 5) == "abc"


def test_unrelated_requests_are_ignored(server):
    _get(server, "favicon.ico", "?code=abc&state=s1")
    assert browser.wait_for_code(server, "s1", 5) == "abc"


def test_state_mismatch(server):
    _get(server, "?code=abc&state=forged")
    with pytest.raises(exceptions.OidcCallbackError, match="state"):
        browser.wait_for_code(server, "s1", 5)


def test_idp_error(server):
    _get(server, "?error=access_denied&error_description=nope&state=s1")
    with pytest.raises(exceptions.OidcCallbackError, match="access_denied"):
        browser.wait_for_code(server, "s1", 5)


def test_timeout(server):
    with pytest.raises(exceptions.OidcCallbackError, match="Timed out"):
        browser.wait_for_code(server, "s1", 0.5)


def test_port_in_use():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        with pytest.raises(exceptions.OidcCallbackError, match="in use"):
            browser.bind_callback_server("127.0.0.1", s.getsockname()[1])


def test_url_is_printed(monkeypatch, capsys):
    opened = []
    monkeypatch.setattr(
        browser.webbrowser, "open", lambda url, **kw: opened.append(url)
    )
    browser.open_browser("https://idp.example.com/auth?x=1")
    assert opened == ["https://idp.example.com/auth?x=1"]
    assert "https://idp.example.com/auth?x=1" in capsys.readouterr().err
