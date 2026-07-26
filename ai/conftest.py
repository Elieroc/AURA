"""Environnement minimal pour la suite de tests.

`config.py` appelle `sys.exit()` à l'import sur toute variable requise absente —
c'est voulu en exploitation (mieux vaut ne pas démarrer que tourner sur une
valeur de repli silencieuse), mais à la collecte pytest ce `SystemExit` se
traduisait par un INTERNALERROR : sans un `.env` complet, la suite ramassait 20
tests sur 89 et abandonnait le reste **sans le signaler**. Les tests concernés
sont pourtant de la logique pure (corrélation, garde-fous, pseudonymisation) et
n'ont besoin d'aucun identifiant réel.

D'où ces bouchons, posés en `setdefault` : un `.env` réellement chargé garde
toujours la main.

Ce qui n'est PAS bouché ici : l'accès au modèle. Le seul test qui appelle
DeepSeek pour de vrai est facturé et sort sur le réseau ; il exige un opt-in
explicite (`SOC_AI_TEST_LLM=1`), jamais la simple présence d'une clé.
"""

import os

for nom, bouchon in (
    ("INDEXER_PASSWORD", "bouchon-de-test"),
    ("PGPASSWORD", "bouchon-de-test"),
    ("DEEPSEEK_API_KEY", "bouchon-de-test"),
):
    os.environ.setdefault(nom, bouchon)
