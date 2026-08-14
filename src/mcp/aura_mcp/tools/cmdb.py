"""Outils CMDB : qui sont les machines, et à quel point elles comptent.

La priorité d'un asset (P1-P4) gouverne l'ordre dans lequel ses incidents sont
analysés, la sévérité qu'ils portent, et le seuil au-delà duquel le modèle n'a
plus le droit de les refermer seul. Elle se déclare à l'enrôlement
(`aura_enroll_agent(role=…)`) ; ces deux outils servent à la LIRE et à la
CORRIGER après coup.

La correction est en `aura:write` et non `aura:admin` : elle ne touche aucune
machine, seulement le classement d'un asset. Elle reste une décision qui compte
— déclasser le contrôleur de domaine en P4 est le meilleur moyen de rendre le
SOC lent là où il devrait être le plus rapide.
"""

from soc_agent import assets as soc_assets
from soc_agent import config as soc_config

from .. import auth, output
from ..server import register


@auth.require("aura:read")
def aura_assets_list(priority: int | None = None,
                     debt_only: bool = False) -> dict:
    """Inventaire des machines surveillées, avec leur priorité SOC.

    `dette_seulement` répond à la question qui compte vraiment : **quelles
    machines tournent sans rôle déclaré ?** Elles sont traitées en P4 — donc en
    fin de file — et rien d'autre ne le signale. Un asset critique oublié à
    l'enrôlement est invisible jusqu'à l'incident qu'on aura analysé trop tard.

    Args:
        priorite: ne rendre que les assets de cette priorité (1 à 4).
        dette_seulement: ne rendre que les assets sans rôle déclaré.
    """
    if priority is not None and not 1 <= int(priority) <= 4:
        return {"error": "priorite hors échelle P1-P4."}

    coverage = soc_assets.coverage()
    if debt_only:
        return output.jsonifiable({
            "dette": coverage["dette"],
            "priorite_appliquee": soc_config.DEFAULT_PRIORITY,
            "assets": coverage["sans_role_declare"],
            "remede": "aura_asset_set(agent_id, role=…) ou, mieux, ranger la "
                      "machine dans son groupe Wazuh role-<role> : la CMDB s'y "
                      "réaligne toute seule au cycle suivant.",
        })
    return output.jsonifiable({
        "assets": soc_assets.list_assets(priority),
        "repartition": coverage["par_priorite"],
        "dette": coverage["dette"],
        "roles_connus": dict(sorted(soc_config.PRIORITY_ROLES.items(),
                                    key=lambda kv: (kv[1], kv[0]))),
    })


@auth.require("aura:write")
def aura_asset_set(agent_id: str, role: str | None = None,
                   priority: int | None = None,
                   notes: str | None = None) -> dict:
    """Classe un asset : son rôle, donc sa priorité. NE TOUCHE PAS la machine.

    Passer `role` est la bonne façon de faire : la priorité en découle et reste
    cohérente avec le catalogue. `priorite` seule est l'échappatoire pour un cas
    que le catalogue ne couvre pas — elle sera marquée `operateur` et ne sera
    plus jamais recalculée depuis les groupes Wazuh.

    Args:
        agent_id: identifiant Wazuh de l'agent (`001`), pas son nom.
        role: rôle du catalogue (`dc`, `web`, `firewall`…).
        priorite: 1 à 4, pour forcer un classement hors catalogue.
        notes: justification, lue par le prochain analyste qui s'interrogera.
    """
    try:
        line = soc_assets.set_asset(agent_id, role=role, priority=priority,
                                   notes=notes)
    except ValueError as e:
        return {"error": str(e)}
    return output.jsonifiable({
        "asset": line,
        "effet": f"les prochains incidents de cet agent naîtront en "
                 f"P{line['priority']} ; les incidents DÉJÀ ouverts gardent "
                 f"la priorité qu'ils avaient (elle est figée à l'ouverture, "
                 f"pour qu'un case reste lisible avec son contexte d'origine).",
    })


register(aura_assets_list)
register(aura_asset_set)
