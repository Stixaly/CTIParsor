"""Authentication and roles (ADR-0097 items 14 and 15).

    config       AUTH_MODE, the session lifetime, the start guard
    passwords    Argon2id hashes
    store        users, sessions, API tokens and the sign-in lockout (tables of migration 18)
    permissions  the minimum role of every operation
    deps         the FastAPI dependency that applies them
"""
