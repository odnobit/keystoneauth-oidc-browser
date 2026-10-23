"""Browser half of the Authorization Code flow.

Opens the identity provider's login page and catches the redirect on a
one-shot HTTP server on localhost. Standard library only.
"""

from __future__ import annotations

import base64
import hashlib
import http.server
import secrets
import sys
import time
import webbrowser
from urllib.parse import parse_qs, urlparse

from keystoneauth_oidc_browser import exceptions

_STYLE = b"""
<style>
:root{--bg:#f6f7f9;--card:#fff;--fg:#1a1d21;--muted:#5f6670;--border:#e3e6ea;
--ok:#16a34a;--ok-bg:#dcfce7;--err:#dc2626;--err-bg:#fee2e2}
@media (prefers-color-scheme:dark){:root{--bg:#0f1115;--card:#171a21;--fg:#e6e8eb;
--muted:#9aa3ad;--border:#262b34;--ok:#4ade80;--ok-bg:#12291b;--err:#f87171;--err-bg:#2c1414}}
*{box-sizing:border-box;margin:0}
html,body{height:100%}
body{display:grid;place-items:center;padding:16px;background:var(--bg);color:var(--fg);
font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;-webkit-font-smoothing:antialiased}
.card{width:100%;max-width:380px;padding:36px 32px;text-align:center;background:var(--card);
border:1px solid var(--border);border-radius:16px;box-shadow:0 8px 30px rgba(0,0,0,.06);
animation:in .35s ease-out}
.icon{width:56px;height:56px;margin:0 auto 20px;border-radius:50%;display:grid;place-items:center}
.ok .icon{background:var(--ok-bg);color:var(--ok)}
.err .icon{background:var(--err-bg);color:var(--err)}
.icon svg{width:28px;height:28px}
.ok .icon path{stroke-dasharray:24;stroke-dashoffset:24;animation:draw .4s .2s ease-out forwards}
h1{font-size:20px;font-weight:600;margin-bottom:6px}
p{color:var(--muted)}
code{font:13px ui-monospace,SFMono-Regular,Menlo,monospace;padding:2px 6px;border-radius:6px;
background:var(--bg);border:1px solid var(--border)}
@keyframes in{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
@keyframes draw{to{stroke-dashoffset:0}}
@media (prefers-reduced-motion:reduce){*{animation:none!important}.ok .icon path{stroke-dashoffset:0}}
</style>
"""

_HEAD = (
    b'<!doctype html><html lang="en"><head><meta charset="utf-8">'
    b'<meta name="viewport" content="width=device-width,initial-scale=1">'
    b'<meta name="robots" content="noindex">'
)

_PAGE = (
    _HEAD
    + b"<title>Authentication complete</title>"
    + _STYLE
    + b'</head><body><main class="card ok" role="status">'
    b'<div class="icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" '
    b'stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
    b'<path d="M5 12.5l4.5 4.5L19 7.5"/></svg></div>'
    b"<h1>Authentication complete</h1>"
    b"<p>You're signed in. You can close this tab and return to the terminal.</p>"
    b"</main><script>setTimeout(function(){try{window.close()}catch(e){}},4500)</script>"
    b"</body></html>"
)

_ERROR_PAGE = (
    _HEAD
    + b"<title>Authentication failed</title>"
    + _STYLE
    + b'</head><body><main class="card err" role="alert">'
    b'<div class="icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" '
    b'stroke-width="2.5" stroke-linecap="round" aria-hidden="true">'
    b'<path d="M12 7v6M12 17h.01"/></svg></div>'
    b"<h1>Authentication failed</h1>"
    b"<p>Something went wrong during sign-in. Return to the terminal for details.</p>"
    b"</main></body></html>"
)


def make_pkce_pair() -> tuple[str, str]:
    """Return a PKCE ``(code_verifier, code_challenge)`` pair (RFC 7636, S256)."""
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


class _CallbackServer(http.server.HTTPServer):
    params: dict | None = None


class _CallbackHandler(http.server.BaseHTTPRequestHandler):
    timeout = 10

    def do_GET(self):
        query = parse_qs(urlparse(self.path).query)
        params = {k: v[0] for k, v in query.items()}

        if "code" in params or "error" in params:
            self.server.params = params
            page = _ERROR_PAGE if "error" in params else _PAGE
            self.send_response(200)
        else:
            page = b""
            self.send_response(404)

        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(page)))
        self.end_headers()
        self.wfile.write(page)

    def log_message(self, format, *args):
        """Do not log requests to stderr."""


def open_browser(url: str) -> None:
    print(
        "Opening the login page in your browser. If it does not open, "
        "visit:\n\n    %s\n" % url,
        file=sys.stderr,
    )
    webbrowser.open(url, new=1, autoraise=True)


def bind_callback_server(host: str, port: int) -> _CallbackServer:
    """Start listening for the redirect.

    Done before the browser is opened, so a fast redirect cannot be missed.
    With ``port`` 0 the OS picks a free port; read it back from
    ``server.server_address``.
    """
    try:
        return _CallbackServer((host, port), _CallbackHandler)
    except OSError as e:
        raise exceptions.OidcCallbackError(
            "Cannot listen for the login redirect on %s:%s (%s). Is another "
            "login in progress, or is the port in use?" % (host, port, e)
        ) from e


def wait_for_code(server: _CallbackServer, expected_state: str, timeout: float) -> str:
    """Wait for the redirect and return the authorization code."""
    deadline = time.monotonic() + timeout
    try:
        while server.params is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise exceptions.OidcCallbackError(
                    "Timed out after %ss waiting for the login to complete "
                    "in the browser." % timeout
                )
            server.timeout = remaining
            try:
                server.handle_request()
            except TimeoutError:
                pass
    finally:
        server.server_close()

    params = server.params
    if "error" in params:
        raise exceptions.OidcCallbackError(
            "The identity provider refused the login: %s %s"
            % (params["error"], params.get("error_description", ""))
        )
    if not secrets.compare_digest(params.get("state", ""), expected_state):
        raise exceptions.OidcCallbackError(
            "The login redirect carried an unexpected state; ignoring it."
        )
    return params["code"]
