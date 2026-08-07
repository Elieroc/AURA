#!/usr/bin/env python3
"""Verifie que chaque agregation de chaque visualisation importee fonctionne
reellement contre l'index pattern qu'elle reference (le _import de saved
objects ne valide PAS les champs -- une visu peut s'importer avec succes puis
afficher 'No results found' ou une erreur d'agregation a l'ouverture).

DEUX controles, et il faut les deux :

1. l'agregation tourne cote OpenSearch (le champ existe et est agregeable) ;
2. le champ figure dans la LISTE MISE EN CACHE de l'index pattern.

Le second a ete ajoute apres coup : `_index` passait le controle 1 sans
probleme -- c'est un champ meta parfaitement agregeable -- mais etait absent de
la liste mise en cache de `soc-ai-all-alerts`, faute de `meta_fields` a la
creation. Resultat : verificateur tout vert, et « Could not locate that
index-pattern-field (id: _index) » a l'ecran. Un controle qui ne teste pas le
meme chemin que le produit ne prouve rien."""
import json
import os
import subprocess

AUTH = f"admin:{os.environ['INDEXER_PASSWORD']}"
DASH = "https://localhost"
IDX = "https://localhost:9200"


def curl(url, data=None, headers=None):
    cmd = ["curl", "-sk", "-u", AUTH, url]
    for h in (headers or []):
        cmd += ["-H", h]
    if data:
        cmd += ["-X", "POST", "-H", "Content-Type: application/json", "-d", json.dumps(data)]
    out = subprocess.run(cmd, capture_output=True, text=True).stdout
    return json.loads(out) if out.strip() else {}


patterns = {}
champs_connus = {}
found = curl(f"{DASH}/api/saved_objects/_find?type=index-pattern&per_page=100")
for o in found.get("saved_objects", []):
    patterns[o["id"]] = o["attributes"]["title"]
    # La liste de champs telle que le dashboard la voit. C'est elle que
    # consulte la visualisation a l'ouverture, pas le mapping OpenSearch.
    champs_connus[o["id"]] = {
        f.get("name") for f in json.loads(o["attributes"].get("fields") or "[]")}

vis = curl(f"{DASH}/api/saved_objects/_find?type=visualization&per_page=100")
ok = bad = 0
for o in vis.get("saved_objects", []):
    vid = o["id"]
    if not vid.startswith("soc-ai-"):
        continue
    state = json.loads(o["attributes"]["visState"])
    idx_ref = next((r["id"] for r in o["references"] if r["type"] == "index-pattern"), None)
    title = patterns.get(idx_ref, idx_ref)
    for agg in state.get("aggs", []):
        p = agg.get("params", {})
        field = p.get("field")
        if not field or agg["type"] == "count":
            continue
        atype = agg["type"]
        if atype == "date_histogram":
            body = {"size": 0, "aggs": {"t": {"date_histogram": {"field": field, "fixed_interval": "1h"}}}}
        elif atype == "geohash_grid":
            body = {"size": 0, "aggs": {"t": {"geohash_grid": {"field": field, "precision": 2}}}}
        else:
            body = {"size": 0, "aggs": {"t": {"terms": {"field": field, "size": 3}}}}
        connus = champs_connus.get(idx_ref) or set()
        if connus and field not in connus:
            print(f"KO  {vid:32s} {atype:16s} {field:45s} "
                  f"absent de la liste de champs de l'index pattern {idx_ref}")
            bad += 1
            continue

        r = curl(f"{IDX}/{title}/_search", data=body)
        if "error" in r:
            reason = r["error"].get("root_cause", [{}])[0].get("reason", "")[:90]
            print(f"KO  {vid:32s} {atype:16s} {field:45s} {reason}")
            bad += 1
        else:
            n = len(r.get("aggregations", {}).get("t", {}).get("buckets", []))
            print(f"ok  {vid:32s} {atype:16s} {field:45s} buckets={n}")
            ok += 1

print(f"\n{ok} agregations OK, {bad} en erreur")
