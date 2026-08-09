#!/usr/bin/env python3
"""Pose le hachage bcrypt d'un compte de l'indexer dans internal_users.yml.

    python3 scripts/set-indexer-password.py kibanaserver
    python3 scripts/set-indexer-password.py admin

Le mot de passe n'est PAS demandé au clavier : il est lu dans le `.env` racine,
seule source de vérité des secrets du stack. Le script ne fait que dériver le
hachage et l'écrire dans `internal_users.yml`, pour que les deux fichiers ne
puissent pas diverger.

Pourquoi ce script existe. `internal_users.yml` est monté tel quel dans
l'indexer : c'est un fichier versionné, alors que le mot de passe vit dans un
`.env` qui ne l'est pas. Sans outil, on est tenté de garder le hachage de
démonstration d'upstream — ce qui laisse le compte accessible avec un mot de
passe publiquement documenté. Ici, rotation = une commande.

Après exécution, redémarrer l'indexer et recharger la configuration de
sécurité :

    docker compose -p aura restart wazuh.indexer
    docker exec -i wazuh.indexer bash -c \\
        '/usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \\
         -f /usr/share/wazuh-indexer/opensearch-security/internal_users.yml \\
         -t internalusers -icl -nhnv \\
         -cacert /usr/share/wazuh-indexer/certs/root-ca.pem \\
         -cert /usr/share/wazuh-indexer/certs/admin.pem \\
         -key /usr/share/wazuh-indexer/certs/admin-key.pem'

Sans ce rechargement, l'indexer continue de servir l'ancienne base d'utilisateurs
depuis son index `.opendistro_security` : le fichier a changé, pas l'état.
"""

import pathlib
import re
import sys

RACINE = pathlib.Path(__file__).resolve().parent.parent
ENV = RACINE / ".env"
USERS = RACINE / "src/wazuh/config/wazuh_indexer/internal_users.yml"

# Compte -> variable du .env qui porte son mot de passe.
COMPTES = {
    "admin": "INDEXER_PASSWORD",
    "kibanaserver": "DASHBOARD_PASSWORD",
}


def lire_env(cle: str) -> str:
    if not ENV.is_file():
        sortir(f"{ENV} introuvable — copier .env.example en .env d'abord.")
    for ligne in ENV.read_text(encoding="utf-8").splitlines():
        ligne = ligne.strip()
        if ligne.startswith(f"{cle}="):
            return ligne.split("=", 1)[1].strip().strip('"').strip("'")
    sortir(f"{cle} absent de {ENV}.")


def sortir(message: str) -> None:
    print(f"erreur : {message}", file=sys.stderr)
    raise SystemExit(1)


def hacher(motdepasse: str) -> str:
    """Hachage bcrypt, par le module Python s'il est là, sinon par l'indexer.

    Le repli n'est pas du confort : `bcrypt` n'est installé ni sur l'hôte de
    production ni dans le venv du soc-agent, alors que l'image de l'indexer
    embarque `hash.sh` — l'outil qui a produit les hachages d'origine. Sans ce
    repli, la rotation demanderait d'installer une dépendance sur le manager
    juste pour poser un mot de passe.
    """
    try:
        import bcrypt
    except ImportError:
        return _hacher_par_conteneur(motdepasse)
    # rounds=12 et préfixe 2b : ce que génère l'outil hash.sh d'OpenSearch.
    return bcrypt.hashpw(motdepasse.encode(), bcrypt.gensalt(12, b"2b")).decode()


def _hacher_par_conteneur(motdepasse: str) -> str:
    """Délègue à `hash.sh` dans le conteneur de l'indexer.

    Le conteneur est retrouvé par son label compose plutôt que par un nom en
    dur : celui-ci dépend du nom de projet (`aura-wazuh.indexer-1`), qui n'est
    pas le même partout.
    """
    import subprocess

    trouve = subprocess.run(
        ["docker", "ps", "--filter",
         "label=com.docker.compose.service=wazuh.indexer",
         "--format", "{{.Names}}"],
        capture_output=True, text=True)
    conteneur = (trouve.stdout or "").split("\n")[0].strip()
    if not conteneur:
        sortir("ni le module bcrypt ni le conteneur wazuh.indexer ne sont "
               "disponibles. Démarrer l'indexer, ou : pip install bcrypt")

    # Le mot de passe passe par l'argument -p, donc par la ligne de commande du
    # conteneur. C'est ce que documente OpenSearch, et le seul lecteur possible
    # est root sur cet hôte — qui a déjà le .env.
    r = subprocess.run(
        ["docker", "exec", "-e", "JAVA_HOME=/usr/share/wazuh-indexer/jdk",
         conteneur,
         "bash", "/usr/share/wazuh-indexer/plugins/opensearch-security/tools/"
                 "hash.sh", "-p", motdepasse],
        capture_output=True, text=True)
    if r.returncode != 0:
        sortir(f"hash.sh a échoué dans {conteneur} : {r.stderr.strip()[:300]}")
    # hash.sh écrit des avertissements avant le hachage : on garde la dernière
    # ligne qui ressemble à du bcrypt.
    for ligne in reversed(r.stdout.splitlines()):
        ligne = ligne.strip()
        if ligne.startswith("$2"):
            return ligne
    sortir(f"hachage introuvable dans la sortie de hash.sh : "
           f"{r.stdout.strip()[:300]}")


def poser(compte: str, hachage: str) -> None:
    texte = USERS.read_text(encoding="utf-8")
    # Remplace la ligne `hash:` du bloc de CE compte seulement : on ancre sur le
    # nom du compte pour ne pas réécrire celui du voisin.
    motif = re.compile(
        rf"(^{re.escape(compte)}:\n(?:[ \t]+.*\n)*?[ \t]+hash:[ \t]*)\S.*$",
        re.MULTILINE)
    nouveau, n = motif.subn(rf'\g<1>"{hachage}"', texte)
    if n != 1:
        sortir(f"bloc « {compte} » introuvable (ou en double) dans {USERS}.")
    USERS.write_text(nouveau, encoding="utf-8")


def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] not in COMPTES:
        sortir(f"usage : {sys.argv[0]} {{{'|'.join(COMPTES)}}}")
    compte = sys.argv[1]
    motdepasse = lire_env(COMPTES[compte])
    if not motdepasse or motdepasse in ("changeme", "__CHANGE_ME__"):
        sortir(f"{COMPTES[compte]} vaut « {motdepasse} » dans {ENV} — "
               f"générer un vrai secret : openssl rand -hex 32")
    poser(compte, hacher(motdepasse))
    print(f"{compte} : hachage posé dans {USERS.relative_to(RACINE)}")
    print("Recharger la configuration de sécurité de l'indexer "
          "(voir l'en-tête de ce script) : sans cela, l'indexer sert "
          "toujours l'ancienne base d'utilisateurs.")


if __name__ == "__main__":
    main()
