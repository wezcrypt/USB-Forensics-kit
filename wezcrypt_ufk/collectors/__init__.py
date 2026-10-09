"""Collector modules. Importing them registers each collector."""

_loaded = False


def load_all() -> None:
    global _loaded
    if _loaded:
        return
    from . import browsers, filesystem, network, windows_activity, windows_system  # noqa: F401,F811

    _loaded = True
