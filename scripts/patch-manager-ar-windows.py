#!/usr/bin/env python3
"""Insère les commandes d'active response Windows/AD dans wazuh_manager.conf.

Ce fichier est gitignoré (il porte les clés d'API VirusTotal / AbuseIPDB) : il
ne peut pas être déployé par `git pull` et doit être édité sur place. On insère
donc les blocs manquants aux ancres, sans réécrire le reste — la copie de prod
contient des réglages absents d'ailleurs (allowed-ips du scanner YARITRUST).

Idempotent : ne fait rien si `win-kill-process` est déjà déclaré.
"""
import shutil
import sys
import time

CHEMIN = sys.argv[1] if len(sys.argv) > 1 else \
    "/opt/AURA/src/wazuh/config/wazuh_cluster/wazuh_manager.conf"

ACTIONS = [
    "win-host-isolate", "win-host-unisolate", "win-kill-process",
    "win-quarantine-file", "win-restore-file", "win-block-ip", "win-allow-ip",
    "ad-disable-account", "ad-enable-account", "ad-remove-group-member",
    "ad-add-group-member",
]

ENTETE = """
  <!--
    ===== Active response Windows / Active Directory =====

    Ces onze commandes manquaient, et c'est ce qui rendait TOUTE la remediation
    Windows inoperante. Le manager genere `shared\\ar.conf` a partir des blocs
    <command> + <active-response> ci-dessous et le pousse aux agents ; l'execd
    de l'agent refuse toute commande absente de ce fichier, sans rien
    journaliser. L'API repond pourtant 200 (elle se contente de transmettre) et
    le soc-agent enregistrait donc la remediation comme partie.

    Consequence mesuree sur un exercice purple-team : des dizaines d'actions
    Windows dans la meme journee - dont la desactivation d'un compte cree par
    l'attaquant et la mise en quarantaine de mimikatz - n'ont strictement rien
    execute. Verifie ensuite sur le controleur de domaine :
    le compte toujours actif, `active-responses.log` sans une seule ligne
    de nos scripts. Le diagnostic initial (« refusees par la safelist du
    script ») etait faux : elles n'ont jamais atteint le script.

    Les blocs vivaient dans src/wazuh/active-response/windows/register-commands.xml,
    qui documentait deja ce piege, mais n'avaient jamais ete reportes ici. Ce
    fichier etant gitignore (cles d'API), ils y sont poses par
    scripts/patch-manager-ar-windows.py.
  -->
"""

CMD = """  <command>
    <name>{n}</name>
    <executable>{n}.exe</executable>
    <timeout_allowed>no</timeout_allowed>
  </command>

"""

AR = """  <active-response>
    <disabled>no</disabled>
    <command>{n}</command>
    <location>local</location>
    <rules_id>999999</rules_id>
  </active-response>

"""

src = open(CHEMIN, encoding="utf-8").read()
if "win-kill-process" in src:
    print("deja present, rien a faire")
    sys.exit(0)

# Ancre 1 : juste apres le bloc <command> de host-allow.
ancre_cmd = """  <command>
    <name>host-allow</name>
    <executable>host-allow.sh</executable>
    <timeout_allowed>no</timeout_allowed>
  </command>
"""
if ancre_cmd not in src:
    sys.exit("ancre <command> host-allow introuvable - fichier inattendu")
src = src.replace(
    ancre_cmd,
    ancre_cmd + ENTETE + "".join(CMD.format(n=n) for n in ACTIONS), 1)

# Ancre 2 : juste apres le bloc <active-response> de host-allow.
ancre_ar = """  <active-response>
    <disabled>no</disabled>
    <command>host-allow</command>
    <location>local</location>
    <rules_id>999999</rules_id>
  </active-response>
"""
if ancre_ar not in src:
    sys.exit("ancre <active-response> host-allow introuvable - fichier inattendu")
src = src.replace(
    ancre_ar,
    ancre_ar + "\n  <!-- Windows / AD. Meme regle inexistante 999999 : aucun "
    "declenchement\n       automatique, seul l'appel API (soc-agent, MCP) "
    "execute l'action. -->\n"
    + "".join(AR.format(n=n) for n in ACTIONS), 1)

# Validation AVANT d'ecrire : un fichier casse ici empeche le manager de
# demarrer. Les commentaires sont retires avant l'analyse, parce que la conf de
# prod en contient un avec « --remote » : illegal en XML strict, tolere par le
# parseur de Wazuh. On valide la structure des balises, pas la typographie des
# commentaires.
import re
import xml.etree.ElementTree as ET

sans_commentaires = re.sub(r"<!--.*?-->", "", src, flags=re.DOTALL)
try:
    ET.fromstring("<root>" + sans_commentaires + "</root>")
except ET.ParseError as e:
    sys.exit(f"XML invalide apres insertion, rien ecrit : {e}")

shutil.copy2(CHEMIN, f"{CHEMIN}.bak.{int(time.time())}")
open(CHEMIN, "w", encoding="utf-8").write(src)
print(f"{len(ACTIONS)} commandes + {len(ACTIONS)} active-response inserees, "
      "structure XML validee")
