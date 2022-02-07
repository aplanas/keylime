"""Utility module for secure directory management."""

import os
from contextlib import contextmanager


def ch_dir(path):
    """Change directory and create it if missing."""
    if not os.path.exists(path):
        os.makedirs(path, 0o700)
    os.chdir(path)


@contextmanager
def create(name, mode="wb", mask=0o600):
    """Create a file with a restrivite umask."""
    f = os.fdopen(os.open(name, os.O_WRONLY | os.O_CREAT, mask), mode)
    try:
        yield f
    finally:
        f.close()
