"""Argon2id hashes of local passwords (argon2-cffi defaults).

`verify` takes the same time for a user that does not exist (`DUMMY_HASH`) as
for one that does, so the answer does not tell which usernames exist.  A password
is never logged.
"""
from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

MIN_LENGTH = 12
MAX_LENGTH = 1024        # Argon2 hashes the whole input: a megabyte password is a way to burn CPU

_hasher = PasswordHasher()                     # Argon2id
DUMMY_HASH = _hasher.hash("not a password anyone has")


def check_policy(password: str) -> None:
    """Raise ValueError when `password` is not acceptable for a new account."""
    if len(password) < MIN_LENGTH:
        raise ValueError(f"the password must have at least {MIN_LENGTH} characters")
    if len(password) > MAX_LENGTH:
        raise ValueError(f"the password must have at most {MAX_LENGTH} characters")


def hash_password(password: str) -> str:
    """Check a new password against the password policy, and return its hash."""
    check_policy(password)
    return _hasher.hash(password)


def verify(password: str, stored_hash: str | None) -> bool:
    """Does `password` match `stored_hash`?  With no hash, the check still runs
    against `DUMMY_HASH` and answers False."""
    if len(password) > MAX_LENGTH:
        password = password[:MAX_LENGTH]
    target = stored_hash or DUMMY_HASH
    try:
        ok = _hasher.verify(target, password)
    except (VerificationError, InvalidHashError):
        return False
    return ok and stored_hash is not None


def rehash(password: str) -> str:
    """A fresh hash of a password that has just been verified: no policy check, so an
    account made under an older policy can still sign in."""
    return _hasher.hash(password)


def needs_rehash(stored_hash: str) -> bool:
    """True when a stored hash was made with other hasher parameters than the current ones, so that it should be made
    again."""
    return _hasher.check_needs_rehash(stored_hash)
