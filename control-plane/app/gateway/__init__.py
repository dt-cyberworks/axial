"""Gateway-Package.

Lazy re-exports: authorize.py haengt (ueber WHITELIST) an app.tools.registry,
die ihrerseits app.gateway.args_safety importiert. Ein eager Import von
authorize hier wuerde daher einen Zyklus registry -> gateway/__init__ ->
authorize -> registry ausloesen. Deshalb werden die Symbole erst bei Zugriff
geladen (PEP 562), sodass `from app.gateway import authorize` weiterhin geht,
ohne den Import-Zyklus.
"""

__all__ = ["authorize", "ToolCall", "Decision"]


def __getattr__(name):
    if name in __all__:
        from app.gateway import authorize as _mod

        return getattr(_mod, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
