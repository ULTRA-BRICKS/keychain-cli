"""`set` on the Secret Service without a bus: the retry/convergence logic and the per-ref lock."""

from __future__ import annotations

import os
import threading
import time

import pytest

from keychainlib.backends import reflock
from keychainlib.backends.secretservice import SecretServiceBackend
from keychainlib.errors import BackendError, NotFound
from keychainlib.refs import Ref

REF = Ref("tool", "token")


class Scripted(SecretServiceBackend):
    """A backend whose store calls follow a script: each `_find` returns the next list."""

    def __init__(self, finds: list[list[str]], update_fails: int = 0) -> None:
        super().__init__()
        self.finds = finds
        self.update_fails = update_fails
        self.log: list[tuple] = []

    def collection(self) -> str:
        return "/org/freedesktop/secrets/collection/test"

    def _ensure_unlocked(self, path, what) -> None:
        pass

    def _find(self, ref):
        return self.finds.pop(0)

    def _create(self, collection, ref, value, label, meta):
        self.log.append(("create", meta))

    def _update(self, item, value, label, meta):
        if self.update_fails:
            self.update_fails -= 1
            raise NotFound("vanished")
        self.log.append(("update", item))

    def _delete_item(self, item, ref):
        self.log.append(("delete", item))


@pytest.fixture(autouse=True)
def _runtime_dir(tmp_path, monkeypatch):
    run = tmp_path / "run"
    run.mkdir(mode=0o700)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(run))


def test_update_of_a_single_item_does_not_search_again():
    b = Scripted([["/c/3"]])
    b.set(REF, b"v", None, None)
    assert b.log == [("update", "/c/3")]


def test_create_then_fold_duplicates_into_the_oldest():
    b = Scripted([[], ["/c/2", "/c/5", "/c/9"]])
    b.set(REF, b"v", None, "note", "https://site.tld")
    assert b.log == [
        ("create", {"note": "note", "origin": "https://site.tld"}),
        ("delete", "/c/5"),
        ("delete", "/c/9"),
    ]


def test_retry_after_the_item_vanished():
    b = Scripted([["/c/3"], [], ["/c/4"]], update_fails=1)
    b.set(REF, b"v", None, None)
    assert b.log == [("create", {"note": None, "origin": None})]


def test_gives_up_after_three_races():
    b = Scripted([["/c/1"], ["/c/2"], ["/c/3"]], update_fails=3)
    with pytest.raises(BackendError):
        b.set(REF, b"v", None, None)


def test_ref_lock_serializes_writers():
    inside, overlaps = [], []

    def writer():
        with reflock.ref_lock("store", "tool", "token"):
            if inside:
                overlaps.append(True)
            inside.append(1)
            time.sleep(0.05)
            inside.pop()

    threads = [threading.Thread(target=writer) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert overlaps == []


def test_ref_lock_names_hide_the_ref(tmp_path):
    with reflock.ref_lock("store", "tool", "token"):
        pass
    names = os.listdir(tmp_path / "run" / "keychain-cli")
    assert len(names) == 1 and "tool" not in names[0] and "token" not in names[0]


def test_ref_lock_refuses_a_shared_directory(tmp_path):
    (tmp_path / "run" / "keychain-cli").mkdir(mode=0o777)
    os.chmod(tmp_path / "run" / "keychain-cli", 0o777)
    with pytest.raises(BackendError), reflock.ref_lock("store", "tool", "token"):
        pass


def test_ref_lock_times_out(monkeypatch):
    with reflock.ref_lock("s", "a", "b"):
        result = []

        def other():
            try:
                with reflock.ref_lock("s", "a", "b", timeout=0.1):
                    result.append("got it")
            except BackendError:
                result.append("timeout")

        t = threading.Thread(target=other)
        t.start()
        t.join()
    assert result == ["timeout"]
