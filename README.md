# keystoneauth-oidc-browser

A [keystoneauth1](https://docs.openstack.org/keystoneauth/latest/) auth plugin that logs in
through the browser (OpenID Connect Authorization Code + PKCE, e.g. Keycloak) and caches
Keystone tokens between runs. It extends upstream `v3oidcauthcode`: the browser opens only when
no usable token is cached.

* **Auth type:** `v3oidcbrowser`
* **Requires:** Python 3.9+, keystoneauth1 5.9.0+

## Installation

```bash
pip install .
# or, into an isolated python-openstackclient
pipx inject python-openstackclient .
```

## Usage

Configure it like upstream `v3oidcauthcode`:

```bash
export OS_AUTH_TYPE=v3oidcbrowser
export OS_AUTH_URL=https://keystone.example.com/v3
export OS_IDENTITY_API_VERSION=3
export OS_IDENTITY_PROVIDER=openstack
export OS_PROTOCOL=openid
export OS_CLIENT_ID=os-keystone-pub          # public client: no secret
export OS_DISCOVERY_ENDPOINT=https://sso.example.com/realms/openstack/.well-known/openid-configuration
export OS_PROJECT_ID=...

openstack token issue   # first run: the browser opens, log in there
openstack server list   # later runs: the cached token, no browser
```

Or in `clouds.yaml`:

```yaml
clouds:
  cloud1:
    auth_type: v3oidcbrowser
    auth:
      auth_url: https://keystone.example.com/v3
      identity_provider: openstack
      protocol: openid
      client_id: os-keystone-pub
      discovery_endpoint: https://sso.example.com/realms/openstack/.well-known/openid-configuration
      project_id: ...
```

### Options

In addition to the upstream `v3oidcauthcode` options:

| Option | Env | Default | Meaning |
|---|---|---|---|
| `--os-redirect-uri` | `OS_REDIRECT_URI` | `http://127.0.0.1` | without a port, a free one is picked |
| `--os-redirect-timeout` | `OS_REDIRECT_TIMEOUT` | `120` | seconds to wait for the browser login |
| `--os-authorization-endpoint` | `OS_AUTHORIZATION_ENDPOINT` | from discovery | override the authorization endpoint |
| `--os-code` | `OS_CODE` | — | use your own authorization code, skip the browser |
| `--os-client-secret` | `OS_CLIENT_SECRET` | — | confidential clients only |
| `--os-token-cache-enabled` | `OS_TOKEN_CACHE_ENABLED` | `true` | `false` disables the cache |
| `--os-token-cache-dir` | `OS_TOKEN_CACHE_DIR` | `~/.cache/keystoneauth/v3oidcbrowser`* | cache location |
| `--os-token-cache-min-ttl` | `OS_TOKEN_CACHE_MIN_TTL` | `300` | minimum remaining validity (s) to reuse a token |

\* Honors `$XDG_CACHE_HOME`; `%LOCALAPPDATA%` on Windows.

## Identity provider setup

* **Keycloak:** set *Valid redirect URIs* to `http://127.0.0.1:*`. Do not register a bare
  `http://127.0.0.1`: Keycloak then redirects to port 80 and the login fails.
* **Fixed port:** set `OS_REDIRECT_URI=http://127.0.0.1:8080` for IdPs that need an exact URI,
  or for remote hosts with port forwarding (`ssh -L 8080:127.0.0.1:8080 ...`).
* **No browser:** the login URL is also printed to the terminal.
* **Parallel commands:** with an empty cache each one starts its own login. Log in once first
  (`openstack token issue`).

## Token cache

* Tokens are cached per cloud (`auth_url`) and scope. Switching projects rescopes without a
  browser login. On a `401`, the plugin rescopes, and logs in again only if that fails.
* Tokens are encrypted (AES-256-GCM) with a key stored in the OS keyring
  ([keyring](https://pypi.org/project/keyring/), service `keystoneauth-v3oidcbrowser`, user
  `cache-key`). Without a keyring (e.g. SSH or CI on Linux), tokens are stored in plain text in
  `0600` files, and a warning is logged.
* The cache is keyed by configuration, not by user. Use a separate `OS_TOKEN_CACHE_DIR` for
  each account on the same cloud.
* To log out, delete the cache directory, run `openstack token revoke`, or run
  `keyring del keystoneauth-v3oidcbrowser cache-key`.
* Works with the openstacksdk keyring cache (`cache: {auth: true}` in `clouds.yaml`).

## Development

```bash
tox                  # unit tests and style checks
tox -e pep8          # pre-commit hooks (ruff, codespell, ...) and mypy
tox -e cover         # coverage, HTML report in cover/
tox -e py3 -- tests/test_plugin.py -k cache   # pass arguments to pytest
pre-commit install   # run the same style checks on every commit
```

Runtime and test dependencies are in `requirements.txt` and `test-requirements.txt`.

### Releasing

The version comes from git tags ([pbr](https://docs.openstack.org/pbr/latest/)); there is no
version in `pyproject.toml`. To release, push a plain semver tag:

```bash
git tag -s 1.2.0 -m "keystoneauth-oidc-browser 1.2.0"
git push origin 1.2.0
```

The `Release` workflow builds the sdist and wheel, publishes them to PyPI (Trusted Publishing)
and creates a GitHub release with generated notes.
