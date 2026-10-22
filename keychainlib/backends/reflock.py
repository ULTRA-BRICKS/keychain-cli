"""Per-ref write lock: writers of one ref on this machine take turns.

The Secret Service has no compare-and-set, so two processes that both search, find nothing and
create can leave two items. Searching again and deleting extras narrows the window but does not
close it (gnome-keyring reuses freed item numbers and a fresh item is not always visible to the
other writer's search yet). An exclusive ``flock`` around search-and-write closes it for every
writer on this machine and uid, which is the only place the store is reachable from anyway.

The lock files live in ``$XDG_RUNTIME_DIR/keychain-cli`` (falling back to
``/run/user/<uid>`` and then the temp dir), named by a hash so a ref never appears in a path.
"""

from __future__ import annotations

import contextlib
import errno
import fcntl
import hashlib
import os
import stat
import tempfile
import time
from collections.abc import Iterator
from pathlib import Path

from ..errors import BackendError

LOCK_TIMEOUT = 330.0  # longer than an unlock prompt (300 s) another writer may be waiting on


def _lock_dir() -> Path:
    uid = os.getuid()
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    if not runtime and os.path.isdir(f"/run/user/{uid}"):
        runtime = f"/run/user/{uid}"
    base = Path(runtime) / "keychain-cli" if runtime else Path(tempfile.gettempdir()) / f"keychain-cli-{uid}"
    try:
        base.mkdir(mode=0o700, parents=True, exist_ok=True)
        st = os.lstat(base)
    except OSError as exc:
        raise BackendError("cannot create the write-lock directory", why=exc.strerror or "") from exc
    # A directory another user created (or a symlink planted in /tmp) would let them hold our
    # locks or swap the files; refuse it rather than write without a lock.
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != uid or st.st_mode & 0o077:
        raise BackendError(
            f"the write-lock directory {base} is not a private directory of this user",
            fix=f"remove it (rm -r {base}) and retry",
        )
    return base


@contextlib.contextmanager
def ref_lock(*key: str, timeout: float = LOCK_TIMEOUT) -> Iterator[None]:
    """Hold an exclusive lock named by ``key`` (store, service, account) for the block."""
    name = hashlib.sha256("\0".join(key).encode("utf-8")).hexdigest()[:32] + ".lock"
    path = _lock_dir() / name
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError as exc:
                if exc.errno not in (errno.EWOULDBLOCK, errno.EAGAIN):
                    raise BackendError("cannot take the write lock", why=exc.strerror or "") from exc
                if time.monotonic() > deadline:
                    raise BackendError(
                        "another keychain process kept the write lock for this ref",
                        why=f"waited {int(timeout)} s",
                    ) from exc
                time.sleep(0.02)
        yield
    finally:
        os.close(fd)  # closing releases the lock
