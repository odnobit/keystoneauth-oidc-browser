"""On-disk store for Keystone tokens.

Every entry lives in its own file, written atomically, so concurrent
``openstack`` processes never see a partial write and never lose each
other's updates. The store knows nothing about keystoneauth: it keeps opaque
strings with an expiry next to them.

The strings are encrypted with AES-256-GCM under a key kept in the
operating system's secret store (macOS Keychain, Windows Credential Manager,
Secret Service on Linux) through ``keyring``. The tokens themselves do not go
there: with the service catalog they outgrow what a Windows credential holds.
Where no keyring is usable (a Linux box without a desktop session, say),
entries are written in plain text and a warning is logged.

Any failure of the store is reported as a miss or ignored. A broken cache
must never stand in the way of authenticating.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
import os
import stat
import sys
import tempfile
import time

import keyring
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

LOG = logging.getLogger(__name__)

CACHE_FORMAT_VERSION = 1

KEYRING_SERVICE = "keystoneauth-v3oidcbrowser"
KEYRING_USERNAME = "cache-key"

_APP_DIR = os.path.join("keystoneauth", "v3oidcbrowser")
_SUFFIX = ".json"
_TMP_PREFIX = ".tmp-"


def default_cache_dir() -> str:
    """Return the per-user cache directory for this platform."""
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser(
            os.path.join("~", "AppData", "Local")
        )
    else:
        base = os.environ.get("XDG_CACHE_HOME") or os.path.expanduser(
            os.path.join("~", ".cache")
        )
    return os.path.join(base, _APP_DIR)


class FileTokenCache:
    """A directory of token files, one per cache key.

    :param cache_dir: where to keep the files, the platform's per-user cache
        directory when not given.
    """

    def __init__(self, cache_dir: str | None = None):
        self.cache_dir = os.path.expanduser(cache_dir or default_cache_dir())
        self._usable: bool | None = None
        self._cipher: AESGCM | None = None
        self._cipher_loaded = False

    def _ensure_dir(self) -> bool:
        """Create the directory if needed and check nobody else can use it.

        The answer is worked out once per instance.
        """
        if self._usable is not None:
            return self._usable

        self._usable = False
        try:
            os.makedirs(self.cache_dir, mode=0o700, exist_ok=True)
            st = os.stat(self.cache_dir)
        except OSError as e:
            LOG.warning("Token cache disabled, cannot use %s: %s", self.cache_dir, e)
            return False

        if hasattr(os, "getuid"):
            if st.st_uid != os.getuid():
                LOG.warning(
                    "Token cache disabled, %s is not owned by the current user",
                    self.cache_dir,
                )
                return False
            if stat.S_IMODE(st.st_mode) & 0o077:
                try:
                    os.chmod(self.cache_dir, 0o700)
                except OSError as e:
                    LOG.warning(
                        "Token cache disabled, cannot restrict access to %s: %s",
                        self.cache_dir,
                        e,
                    )
                    return False

        self._usable = True
        return True

    def _get_cipher(self) -> AESGCM | None:
        """Return the cipher keyed from the keyring, None without a keyring.

        The key is created on first use. The answer is worked out once per
        instance.
        """
        if self._cipher_loaded:
            return self._cipher
        self._cipher_loaded = True

        try:
            key = _get_or_create_key()
        except Exception as e:
            LOG.debug("Keyring unavailable: %s", e)
            key = None

        if key is None:
            LOG.warning(
                "No usable keyring, Keystone tokens are cached unencrypted in %s",
                self.cache_dir,
            )
        else:
            self._cipher = AESGCM(key)
        return self._cipher

    @staticmethod
    def _name(key: str) -> str:
        return hashlib.sha256(key.encode("utf-8")).hexdigest()

    def _path(self, key: str) -> str:
        return os.path.join(self.cache_dir, self._name(key) + _SUFFIX)

    def get(self, key: str) -> str | None:
        """Return the state stored under ``key``, or None.

        An entry that cannot be read back is removed.
        """
        if not self._ensure_dir():
            return None

        path = self._path(key)
        try:
            with open(path, encoding="utf-8") as f:
                entry = json.load(f)
        except FileNotFoundError:
            return None
        except (OSError, ValueError) as e:
            LOG.debug("Discarding unreadable token cache entry %s: %s", path, e)
            self._unlink(path)
            return None

        if not isinstance(entry, dict) or entry.get("version") != CACHE_FORMAT_VERSION:
            LOG.debug("Discarding token cache entry %s in an unknown format", path)
            self._unlink(path)
            return None

        if "ciphertext" in entry:
            cipher = self._get_cipher()
            if cipher is None:
                return None
            try:
                return cipher.decrypt(
                    base64.b64decode(entry["nonce"], validate=True),
                    base64.b64decode(entry["ciphertext"], validate=True),
                    self._name(key).encode("ascii"),
                ).decode("utf-8")
            except (KeyError, TypeError, ValueError, binascii.Error, InvalidTag) as e:
                LOG.debug("Discarding undecryptable token cache entry %s: %s", path, e)
                self._unlink(path)
                return None

        if isinstance(entry.get("state"), str) and self._get_cipher() is None:
            return entry["state"]

        LOG.debug("Discarding token cache entry %s", path)
        self._unlink(path)
        return None

    def set(self, key: str, state: str, expires_at: float) -> None:
        """Store ``state`` under ``key`` until ``expires_at`` (a UNIX time)."""
        if not self._ensure_dir():
            return

        cipher = self._get_cipher()
        if cipher is None:
            entry = {
                "version": CACHE_FORMAT_VERSION,
                "expires_at": expires_at,
                "state": state,
            }
        else:
            nonce = os.urandom(12)
            ciphertext = cipher.encrypt(
                nonce, state.encode("utf-8"), self._name(key).encode("ascii")
            )
            entry = {
                "version": CACHE_FORMAT_VERSION,
                "expires_at": expires_at,
                "nonce": base64.b64encode(nonce).decode("ascii"),
                "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            }
        path = self._path(key)
        tmp_path = None
        try:
            fd, tmp_path = tempfile.mkstemp(
                prefix=_TMP_PREFIX, suffix=_SUFFIX, dir=self.cache_dir
            )
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(entry, f)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, path)
            tmp_path = None
        except OSError as e:
            LOG.debug("Could not write token cache entry %s: %s", path, e)
        finally:
            if tmp_path is not None:
                self._unlink(tmp_path)

        self.purge_expired()

    def delete(self, key: str) -> None:
        if not self._ensure_dir():
            return
        self._unlink(self._path(key))

    def purge_expired(self) -> None:
        """Remove entries whose token has expired."""
        now = time.time()
        try:
            names = os.listdir(self.cache_dir)
        except OSError:
            return

        for name in names:
            if name.startswith(_TMP_PREFIX) or not name.endswith(_SUFFIX):
                continue
            path = os.path.join(self.cache_dir, name)
            try:
                with open(path, encoding="utf-8") as f:
                    expires_at = float(json.load(f)["expires_at"])
            except (OSError, ValueError, TypeError, KeyError):
                continue
            if expires_at <= now:
                self._unlink(path)

    @staticmethod
    def _unlink(path: str) -> None:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        except OSError as e:
            LOG.debug("Could not remove %s: %s", path, e)


def _get_or_create_key() -> bytes | None:
    """Return the cache key from the keyring, creating it if there is none.

    None means the keyring does not keep what it is given (the null backend).
    """
    stored = keyring.get_password(KEYRING_SERVICE, KEYRING_USERNAME)
    if stored is None:
        keyring.set_password(
            KEYRING_SERVICE,
            KEYRING_USERNAME,
            base64.b64encode(AESGCM.generate_key(bit_length=256)).decode("ascii"),
        )
        stored = keyring.get_password(KEYRING_SERVICE, KEYRING_USERNAME)
        if stored is None:
            return None

    try:
        key = base64.b64decode(stored, validate=True)
    except (binascii.Error, ValueError):
        key = b""
    if len(key) != 32:
        raise ValueError(f"{KEYRING_SERVICE} keyring entry is not a 256-bit key")
    return key
