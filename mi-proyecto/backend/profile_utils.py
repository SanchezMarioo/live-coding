from typing import Any


def level_from_contributions(contributions: int) -> dict[str, Any]:
    if contributions >= 50:
        return {"name": "Leyenda", "rank": 5}
    if contributions >= 25:
        return {"name": "Experto", "rank": 4}
    if contributions >= 10:
        return {"name": "Avanzado", "rank": 3}
    if contributions >= 3:
        return {"name": "Colaborador", "rank": 2}
    return {"name": "Nuevo", "rank": 1}


def build_display_name(first_name: str, last_name: str, username: str) -> str:
    full_name = f"{first_name} {last_name}".strip()
    return full_name if full_name else username
