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

ROOT = pathlib.Path(__file__).resolve().parent.parent
ENV = ROOT / ".env"
USERS = ROOT / "src/wazuh/config/wazuh_indexer/internal_users.yml"

# Compte -> variable du .env qui porte son mot de passe.
ACCOUNTS = {
    "admin": "INDEXER_PASSWORD",
    "kibanaserver": "DASHBOARD_PASSWORD",
}


def read_env(key: str) -> str:
    if not ENV.is_file():
        exit_with(f"{ENV} introuvable — copier .env.example en .env d'abord.")
    for line in ENV.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith(f"{key}="):
            return line.split("=", 1)[1].strip().strip('"').strip("'")
    exit_with(f"{key} absent de {ENV}.")


def exit_with(message: str) -> None:
    print(f"erreur : {message}", file=sys.stderr)
    raise SystemExit(1)


def hash(password: str) -> str:
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
        return _hash_in_container(password)
    # rounds=12 et préfixe 2b : ce que génère l'outil hash.sh d'OpenSearch.
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(12, b"2b")).decode()


def _hash_in_container(password: str) -> str:
    """Délègue à `hash.sh` dans le conteneur de l'indexer.

    Le conteneur est retrouvé par son label compose plutôt que par un nom en
    dur : celui-ci dépend du nom de projet (`aura-wazuh.indexer-1`), qui n'est
    pas le même partout.
    """
    import subprocess

    found = subprocess.run(
        ["docker", "ps", "--filter",
         "label=com.docker.compose.service=wazuh.indexer",
         "--format", "{{.Names}}"],
        capture_output=True, text=True)
    container = (found.stdout or "").split("\n")[0].strip()
    if not container:
        exit_with("ni le module bcrypt ni le conteneur wazuh.indexer ne sont "
               "disponibles. Démarrer l'indexer, ou : pip install bcrypt")

    # Le mot de passe passe par l'argument -p, donc par la ligne de commande du
    # conteneur. C'est ce que documente OpenSearch, et le seul lecteur possible
    # est root sur cet hôte — qui a déjà le .env.
    r = subprocess.run(
        ["docker", "exec", "-e", "JAVA_HOME=/usr/share/wazuh-indexer/jdk",
         container,
         "bash", "/usr/share/wazuh-indexer/plugins/opensearch-security/tools/"
                 "hash.sh", "-p", password],
        capture_output=True, text=True)
    if r.returncode != 0:
        exit_with(f"hash.sh a échoué dans {container} : {r.stderr.strip()[:300]}")
    # hash.sh écrit des avertissements avant le hachage : on garde la dernière
    # ligne qui ressemble à du bcrypt.
    for line in reversed(r.stdout.splitlines()):
        line = line.strip()
        if line.startswith("$2"):
            return line
    exit_with(f"hachage introuvable dans la sortie de hash.sh : "
           f"{r.stdout.strip()[:300]}")


def set(account: str, hashing: str) -> None:
    text = USERS.read_text(encoding="utf-8")
    # Remplace la ligne `hash:` du bloc de CE compte seulement : on ancre sur le
    # nom du compte pour ne pas réécrire celui du voisin.
    pattern = re.compile(
        rf"(^{re.escape(account)}:\n(?:[ \t]+.*\n)*?[ \t]+hash:[ \t]*)\S.*$",
        re.MULTILINE)
    new, n = pattern.subn(rf'\g<1>"{hashing}"', text)
    if n != 1:
        exit_with(f"bloc « {account} » introuvable (ou en double) dans {USERS}.")
    USERS.write_text(new, encoding="utf-8")


def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] not in ACCOUNTS:
        exit_with(f"usage : {sys.argv[0]} {{{'|'.join(ACCOUNTS)}}}")
    account = sys.argv[1]
    password = read_env(ACCOUNTS[account])
    if not password or password in ("changeme", "__CHANGE_ME__"):
        exit_with(f"{ACCOUNTS[account]} vaut « {password} » dans {ENV} — "
               f"générer un vrai secret : openssl rand -hex 32")
    set(account, hash(password))
    print(f"{account} : hachage posé dans {USERS.relative_to(ROOT)}")
    print("Recharger la configuration de sécurité de l'indexer "
          "(voir l'en-tête de ce script) : sans cela, l'indexer sert "
          "toujours l'ancienne base d'utilisateurs.")


if __name__ == "__main__":
    main()
