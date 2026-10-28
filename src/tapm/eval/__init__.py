"""Evaluation harness and pre-commitment verification."""


def __getattr__(name: str):
    if name in {"PrecommitReport", "verify_precommitment", "verify_all_precommitments", "verify_precommitment_cli"}:
        from . import precommit
        return getattr(precommit, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "PrecommitReport",
    "verify_precommitment",
    "verify_all_precommitments",
    "verify_precommitment_cli",
]
