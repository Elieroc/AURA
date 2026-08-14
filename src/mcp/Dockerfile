# Contexte de build : ../ (le dossier src/), pas ce dossier — l'image embarque
# le paquet soc_agent tel quel. Les outils MCP appellent le vrai code du
# pipeline (mêmes garde-fous, mêmes requêtes) plutôt que d'en recopier une
# version qui dériverait en silence.
FROM python:3.12-slim

# openssh-client : mitigate.etat_isolation et l'enrôlement d'agent Linux
# passent par ssh. Sans lui, ces outils échouent à l'exécution seulement.
#
# zstd et age : les outils de threat hunting restaurent une archive froide, donc
# la déchiffrent et la décompressent (soc_agent.hunting -> soc_agent.archive).
# Mêmes binaires que l'image du pipeline, pour que la même archive se relise de
# la même façon des deux côtés.
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-client zstd age \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY ai/soc_agent/requirements.txt /tmp/soc-agent.txt
COPY mcp/requirements.txt /tmp/aura-mcp.txt
RUN pip install --no-cache-dir -r /tmp/soc-agent.txt -r /tmp/aura-mcp.txt

COPY ai/soc_agent/ soc_agent/
COPY mcp/aura_mcp/ aura_mcp/

CMD ["python", "-m", "aura_mcp"]
