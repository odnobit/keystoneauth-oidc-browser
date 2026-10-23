import json
import os
import stat
import time

import keyring
import pytest
from keyring.backends import fail, null

from keystoneauth_oidc_browser import token_cache
from keystoneauth_oidc_browser.token_cache import FileTokenCache, default_cache_dir


@pytest.fixture
def cache_dir(tmp_path):
    return str(tmp_path / "cache")


def _mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


def test_roundtrip_and_permissions(cache_dir):
    cache = FileTokenCache(cache_dir)
    cache.set("k", "state", time.time() + 3600)

    assert cache.get("k") == "state"
    assert _mode(cache_dir) == 0o700
    (entry,) = os.listdir(cache_dir)
    assert entry.endswith(".json") and "k" not in entry
    assert _mode(os.path.join(cache_dir, entry)) == 0o600


def test_missing_key(cache_dir):
    assert FileTokenCache(cache_dir).get("nope") is None


def test_delete(cache_dir):
    cache = FileTokenCache(cache_dir)
    cache.set("k", "state", time.time() + 3600)
    cache.delete("k")
    cache.delete("k")
    assert cache.get("k") is None


@pytest.mark.parametrize(
    "content",
    [
        "{not json",
        '{"version": 1, "state": "x"',
        json.dumps({"version": 999, "expires_at": 0, "state": "x"}),
        json.dumps({"version": 1, "expires_at": 0, "state": 42}),
        json.dumps(["a list"]),
        # Plain text entries are not trusted once there is a key.
        json.dumps({"version": 1, "expires_at": 0, "state": "x"}),
        json.dumps({"version": 1, "expires_at": 0, "nonce": "!!", "ciphertext": "x"}),
        json.dumps({"version": 1, "expires_at": 0, "ciphertext": "AAAA"}),
    ],
)
def test_bad_entries_are_discarded(cache_dir, content):
    cache = FileTokenCache(cache_dir)
    cache.set("k", "state", time.time() + 3600)
    path = cache._path("k")
    with open(path, "w") as f:
        f.write(content)

    assert cache.get("k") is None
    assert not os.path.exists(path)


def _read(path):
    with open(path) as f:
        return json.load(f)


def test_tokens_are_encrypted_on_disk(cache_dir, memory_keyring):
    cache = FileTokenCache(cache_dir)
    cache.set("k", "secret-token", time.time() + 3600)

    entry = _read(cache._path("k"))
    assert entry["version"] == token_cache.CACHE_FORMAT_VERSION
    assert "state" not in entry and "ciphertext" in entry
    assert "secret-token" not in json.dumps(entry)
    assert (
        token_cache.KEYRING_SERVICE,
        token_cache.KEYRING_USERNAME,
    ) in memory_keyring.passwords
    # A new process reuses the key.
    assert FileTokenCache(cache_dir).get("k") == "secret-token"


def test_tampered_ciphertext_is_discarded(cache_dir):
    cache = FileTokenCache(cache_dir)
    cache.set("k", "state", time.time() + 3600)
    path = cache._path("k")
    entry = _read(path)
    entry["ciphertext"] = entry["ciphertext"][::-1]
    with open(path, "w") as f:
        json.dump(entry, f)

    assert cache.get("k") is None
    assert not os.path.exists(path)


def test_entry_moved_to_another_key_is_discarded(cache_dir):
    cache = FileTokenCache(cache_dir)
    cache.set("a", "state", time.time() + 3600)
    os.replace(cache._path("a"), cache._path("b"))

    assert cache.get("b") is None


def test_replaced_keyring_key_is_a_miss(cache_dir, memory_keyring):
    FileTokenCache(cache_dir).set("k", "state", time.time() + 3600)
    memory_keyring.passwords.clear()

    assert FileTokenCache(cache_dir).get("k") is None


@pytest.mark.parametrize("backend", [fail.Keyring, null.Keyring])
def test_without_keyring_tokens_are_kept_in_plain_text(cache_dir, backend, caplog):
    keyring.set_keyring(backend())
    cache = FileTokenCache(cache_dir)
    cache.set("k", "state", time.time() + 3600)

    assert _read(cache._path("k"))["state"] == "state"
    assert FileTokenCache(cache_dir).get("k") == "state"
    assert "unencrypted" in caplog.text


def test_encrypted_entry_without_keyring_is_kept(cache_dir):
    cache = FileTokenCache(cache_dir)
    cache.set("k", "state", time.time() + 3600)
    keyring.set_keyring(fail.Keyring())

    assert FileTokenCache(cache_dir).get("k") is None
    assert os.path.exists(cache._path("k"))


def test_purge_expired(cache_dir):
    cache = FileTokenCache(cache_dir)
    cache.set("old", "state", time.time() - 10)
    cache.set("new", "state", time.time() + 3600)

    assert cache.get("old") is None
    assert cache.get("new") == "state"
    assert len(os.listdir(cache_dir)) == 1


@pytest.mark.skipif(not hasattr(os, "getuid"), reason="POSIX only")
def test_loose_permissions_are_tightened(cache_dir):
    os.makedirs(cache_dir)
    os.chmod(cache_dir, 0o777)

    cache = FileTokenCache(cache_dir)
    cache.set("k", "state", time.time() + 3600)

    assert _mode(cache_dir) == 0o700
    assert cache.get("k") == "state"


@pytest.mark.skipif(not hasattr(os, "getuid"), reason="POSIX only")
def test_foreign_directory_disables_cache(cache_dir, monkeypatch):
    os.makedirs(cache_dir)
    monkeypatch.setattr(os, "getuid", lambda: os.stat(cache_dir).st_uid + 1)

    cache = FileTokenCache(cache_dir)
    cache.set("k", "state", time.time() + 3600)

    assert cache.get("k") is None
    assert os.listdir(cache_dir) == []


def test_unwritable_location_disables_cache(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("")

    cache = FileTokenCache(str(blocker / "cache"))
    cache.set("k", "state", time.time() + 3600)

    assert cache.get("k") is None


def test_default_dir_honours_xdg(monkeypatch, tmp_path):
    monkeypatch.setattr("sys.platform", "linux")
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    assert default_cache_dir() == os.path.join(
        str(tmp_path), "keystoneauth", "v3oidcbrowser"
    )
