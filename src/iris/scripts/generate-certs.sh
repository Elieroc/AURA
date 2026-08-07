#!/usr/bin/env bash
#
# Génère la PKI locale de DFIR-IRIS : une CA racine + un certificat serveur
# pour nginx.
#
# Pourquoi ne pas prendre ceux du dépôt upstream : iris-web versionne des
# certificats de développement, clé privée comprise. Elle est publique sur
# GitHub, donc n'importe qui peut déchiffrer le trafic ou se faire passer pour
# l'interface. Ils ne doivent jamais servir ailleurs qu'en démo jetable.
#
# Idempotent : ne réécrit rien si les fichiers existent déjà (--force pour
# régénérer — invalide les sessions en cours et fait râler les navigateurs).

set -euo pipefail

CERT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/certificates"
CA_DIR="${CERT_DIR}/rootCA"
WEB_DIR="${CERT_DIR}/web_certificates"
# .env vit désormais à la racine du dépôt (compose racine unique), pas dans
# src/iris/ : src/iris/scripts -> src/iris -> src -> racine.
ROOT_ENV="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/.env"

FORCE=0
[[ "${1:-}" == "--force" ]] && FORCE=1

# SERVER_NAME doit correspondre à celui du .env, sinon le SAN ne couvre pas le
# nom utilisé et le navigateur refuse le certificat.
SERVER_NAME="iris.soc.local"
if [[ -f "${ROOT_ENV}" ]]; then
    SERVER_NAME="$(grep -E '^SERVER_NAME=' "${ROOT_ENV}" | cut -d= -f2- || echo "iris.soc.local")"
fi

if [[ -f "${WEB_DIR}/iris_cert.pem" && "${FORCE}" -eq 0 ]]; then
    echo "Certificats déjà présents dans ${WEB_DIR} — rien à faire."
    echo "Pour régénérer : $0 --force"
    exit 0
fi

mkdir -p "${CA_DIR}" "${WEB_DIR}"

# La clé serveur appartient à l'uid 33 (cf. plus bas), donc on ne peut pas
# l'écraser sans sudo.
[[ "${FORCE}" -eq 1 && -f "${WEB_DIR}/iris_key.pem" ]] && sudo rm -f "${WEB_DIR}/iris_key.pem"

echo "==> CA racine (10 ans)"
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
    -keyout "${CA_DIR}/irisRootCAKey.pem" \
    -out "${CA_DIR}/irisRootCACert.pem" \
    -subj "/C=FR/O=Aura-SOC/CN=Aura-SOC IRIS Root CA"

echo "==> Certificat serveur pour ${SERVER_NAME} (2 ans)"
openssl req -newkey rsa:2048 -sha256 -nodes \
    -keyout "${WEB_DIR}/iris_key.pem" \
    -out "${WEB_DIR}/iris.csr" \
    -subj "/C=FR/O=Aura-SOC/CN=${SERVER_NAME}"

# SAN large : on accède à l'UI aussi bien par localhost que par le nom logique.
openssl x509 -req -in "${WEB_DIR}/iris.csr" -sha256 -days 730 \
    -CA "${CA_DIR}/irisRootCACert.pem" \
    -CAkey "${CA_DIR}/irisRootCAKey.pem" \
    -CAcreateserial \
    -out "${WEB_DIR}/iris_cert.pem" \
    -extfile <(printf 'subjectAltName=DNS:%s,DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' "${SERVER_NAME}")

rm -f "${WEB_DIR}/iris.csr"

# La clé de CA ne sert qu'ici, sur l'hôte : elle reste à nous, en 600.
chmod 600 "${CA_DIR}/irisRootCAKey.pem"
chmod 644 "${CA_DIR}/irisRootCACert.pem" "${WEB_DIR}/iris_cert.pem"

# La clé serveur, elle, est lue par nginx qui tourne en uid 33 (www-data) dans
# le conteneur. On la lui donne en 640 plutôt que de la passer en 644 : un
# world-readable rendrait la clé TLS lisible par n'importe quel compte de
# l'hôte. D'où le sudo — seul endroit du script qui en a besoin.
chmod 640 "${WEB_DIR}/iris_key.pem"
echo "==> chown de la clé serveur vers l'uid nginx du conteneur (sudo)"
sudo chown 33:33 "${WEB_DIR}/iris_key.pem"

echo
echo "Terminé :"
echo "  CA        ${CA_DIR}/irisRootCACert.pem"
echo "  Serveur   ${WEB_DIR}/iris_cert.pem"
echo
echo "Le navigateur signalera un émetteur inconnu tant que la CA n'est pas"
echo "importée dans son magasin de confiance."
