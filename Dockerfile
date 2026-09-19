# =============================================================================
#  Portail chercheur de l'enclave sécurisée — INSTAD
#
#  Seule surface exposée aux utilisateurs. Cette image ne reçoit JAMAIS la
#  clé de l'agent Samba : le portail ne peut ni créer, ni modifier, ni
#  révoquer un accès — il lit le registre, il ne l'écrit pas.
#
#  Deux étapes : l'interface Vue est construite, puis seuls ses fichiers
#  compilés partent dans l'image finale.
# =============================================================================

# --- Étape 1 : construction de la console ------------------------------------
FROM node:22-alpine AS console

WORKDIR /build

# Les dépendances d'abord : cette couche est réutilisée tant que le
# package.json ne change pas.
COPY console/package.json console/package-lock.json* ./
RUN npm ci --no-audit --no-fund

COPY console/ ./
RUN npm run build


# --- Étape 2 : image finale ---------------------------------------------------
FROM node:22-alpine

# tini : sans lui, Node tourne en PID 1 et n'y reçoit pas SIGTERM — le
# conteneur mettrait dix secondes à s'arrêter, à chaque fois.
# openssh-client : l'API parle aux agents contraints par commande forcée SSH.
# openssl : vérifie le mot de passe d'un chercheur contre l'empreinte
#   SHA-512-crypt ($6$) du registre. Node ne sait pas calculer ce format —
#   `scrypt` en est un autre — et on n'écrit pas de cryptographie maison.
RUN apk add --no-cache tini openssh-client openssl

WORKDIR /app

COPY serveur/package.json ./
RUN npm install --omit=dev --no-audit --no-fund && npm cache clean --force

COPY serveur/ ./
COPY --from=console /build/dist ./console

# Compte non privilégié. L'image ne contient aucun secret : le jeton Proxmox,
# la clé de l'agent snippet et PORTAIL_SECRET sont injectés à l'exécution.
RUN addgroup -g 10001 enclave \
 && adduser -D -u 10001 -G enclave enclave \
 && mkdir -p /app/etat \
 && chown -R enclave:enclave /app/etat

USER enclave

ENV NODE_ENV=production \
    PORTAIL_PORT=8091 \
    PORTAIL_HOTE=0.0.0.0 \
    PORTAIL_SECRETS=/app/etat/second-facteur.json \
    PORTAIL_JOURNAL=/app/etat/journal.jsonl \
    ORCHESTRATEUR_CHEMIN=/opt/enclave/orchestrateur/services

# Les secrets de second facteur et le journal doivent survivre au conteneur.
VOLUME ["/app/etat"]

EXPOSE 8091

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORTAIL_PORT||8091)+'/api/moi').then(r=>process.exit(r.status===401?0:1)).catch(()=>process.exit(1))"

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "index.js"]
