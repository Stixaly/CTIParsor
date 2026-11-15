"""The API's rate limiter (slowapi), kept apart from `api.main` (issue #863).

The route modules decorate their endpoints with `@limiter.limit(...)`.  They took the
limiter from `api.main`, which imports them in turn, so a route module imported first
met a half-initialised `api.main`.  The limiter has no dependency of its own, so it
lives here; `api.main` re-exports it and `api.main.limiter` is still the same object.
"""
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
