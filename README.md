# Portail chercheur de l'enclave sécurisée

Entrée des chercheurs dans l'**enclave sécurisée d'accès aux données** de
l'INSTAD — Institut de la Statistique de Djibouti.

Un chercheur s'authentifie, une machine virtuelle neuve est créée pour lui, ses
partages y sont montés avec son propre mot de passe, et sa session RDP s'ouvre
dans le navigateur. À la déconnexion, la machine est détruite ; son travail, lui,
vit sur le serveur de fichiers.

## Le second facteur est ici, et pas ailleurs

L'extension `auth-json` de Guacamole **contourne sa propre authentification**,
TOTP compris : un jeton signé ouvre la session sans passer par son écran de
connexion. Constaté sur le prototype, `TOTP_ENABLED` étant pourtant actif.

Le portail est donc le seul endroit où un second facteur s'applique réellement
au chercheur. TOTP selon la RFC 6238, sur le `createHmac` de la plateforme —
vérifié contre les six vecteurs de test de la RFC, avec refus du rejeu.

## Ce que le portail ne peut pas faire

C'est la seule surface exposée aux utilisateurs. Il ne reçoit donc **jamais la
clé de l'agent Samba** : il ne peut ni créer, ni modifier, ni révoquer un accès.
Il lit le registre, il ne l'écrit pas.

| | Portail | Console d'administration |
|---|---|---|
| Exposition | 443, tout le monde | 8443, restreint par IP |
| Clé agent snippet | oui | oui |
| **Clé agent Samba** | **non** | oui |
| Registre des accès | lecture seule | lecture / écriture |

## Le parcours

1. Identifiant et mot de passe, vérifiés contre l'empreinte du registre
2. Première connexion : enrôlement d'une application d'authentification
3. Code à six chiffres, à usage unique
4. La session se prépare — environ deux minutes, avec un compteur visible
5. Redirection vers Guacamole, la session s'ouvre sur l'application

## Démarrage

```bash
docker compose up -d           # voir deploiement/docker-compose.yml
```

Les accès chercheurs se créent depuis la console d'administration
([enclave-admin](https://github.com/ashraf-m-aden/enclave-admin)).

## Développement

```bash
cd console && npm install && npm run dev    # http://localhost:5181
cd serveur && node index.js                 # http://127.0.0.1:8091
```

Vue 3 · TypeScript · Composition API · SCSS · Vite — côté serveur Node 22 et
Express 5.
