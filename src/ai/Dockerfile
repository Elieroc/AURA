FROM python:3.12-slim
# zstd et age : la chaîne d'archivage à froid (soc_agent.archive) compresse et
# chiffre par des TUBES, jamais en mémoire ni en clair sur disque. Les deux
# binaires sont donc nécessaires, et deux paquets de quelques centaines de Ko
# sont moins coûteux que d'embarquer une implémentation maison de l'un ou de
# l'autre — surtout pour de la crypto.
RUN apt-get update \
 && apt-get install -y --no-install-recommends zstd age \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY soc_agent/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY soc_agent/ soc_agent/
