"""Oeffentlicher Tool-Katalog aus der Capability-Registry.

Nicht engagement-spezifisch: liefert die maschinenlesbare Capability-Matrix
(welche Tools installiert/freigegeben/gemappt/dispatcht/geparst sind). Quelle
fuer die Operator-Konsole (Tool-Grant-Matrix, Kap. 2.2 der UI-Spec), den
Worker (Dispatch-Verfuegbarkeit) und die Doku - eine Quelle statt vier.
"""

from fastapi import APIRouter

from app.tools import registry

router = APIRouter(prefix="/tools", tags=["tools"])


@router.get("/capabilities")
def capabilities():
    return {
        "tools": registry.capability_matrix(),
        "whitelist": {cat: sorted(names) for cat, names in registry.enabled_whitelist().items()},
        "enabled_but_not_installed": registry.enabled_but_not_installed(),
    }
