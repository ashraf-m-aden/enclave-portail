'use strict';
/**
 * =============================================================================
 *  PORTAIL CHERCHEUR — authentification
 *
 *  Le portail est le service EXPOSÉ aux utilisateurs. Il ne détient donc
 *  volontairement PAS la clé de l'agent Samba : il ne peut ni créer, ni
 *  modifier, ni révoquer un accès. Il lit le registre, il ne l'écrit pas.
 *
 *  Le mot de passe en clair ne sert qu'à deux choses, dans la même seconde :
 *  vérifier l'identité, puis ouvrir la session — le clone en a besoin pour son
 *  compte Unix, et `pam_mount` pour monter les partages. Il n'est jamais
 *  stocké, jamais journalisé.
 * =============================================================================
 */

const { execFile } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const totp = require('./totp');

const REGISTRE = process.env.ENCLAVE_ETAT
  || '/opt/enclave/orchestrateur/etat/acces.json';
const SECRETS = process.env.PORTAIL_SECRETS
  || path.join(__dirname, 'etat', 'second-facteur.json');

const DUREE_SESSION_MS = 30 * 60 * 1000;   // le temps d'ouvrir une session
const TENTATIVES_MAX = 5;
const BLOCAGE_MS = 15 * 60 * 1000;

const SECRET_COOKIE = process.env.PORTAIL_SECRET
  || crypto.randomBytes(32).toString('hex');

const tentatives = new Map();

// ---------------------------------------------------------------------------
// Registre des accès — LECTURE SEULE
// ---------------------------------------------------------------------------

function lireRegistre() {
  try {
    return JSON.parse(fs.readFileSync(REGISTRE, 'utf8'));
  } catch {
    return {};
  }
}

/**
 * Vérifie un mot de passe contre l'empreinte SHA-512-crypt du registre.
 *
 * Node ne sait pas calculer ce format — `scrypt` en est un autre — donc on
 * passe par `openssl`, avec le sel extrait de l'empreinte stockée. Le mot de
 * passe arrive par l'entrée standard : en argument, il serait visible dans le
 * `ps` de n'importe quel utilisateur de la machine.
 */
function verifierMotDePasse(motDePasse, empreinte) {
  return new Promise((resolve) => {
    const champs = String(empreinte).split('$');   // ['', '6', sel, hachage]
    if (champs.length !== 4 || champs[1] !== '6') return resolve(false);
    const sel = champs[2];

    const p = execFile('openssl', ['passwd', '-6', '-salt', sel, '-stdin'],
      { timeout: 10000 }, (err, stdout) => {
        if (err) return resolve(false);
        const a = Buffer.from(stdout.trim());
        const b = Buffer.from(String(empreinte));
        resolve(a.length === b.length && crypto.timingSafeEqual(a, b));
      });
    p.stdin.end(motDePasse);
  });
}

// ---------------------------------------------------------------------------
// Second facteur — le portail en est propriétaire
// ---------------------------------------------------------------------------

function lireSecrets() {
  try {
    return JSON.parse(fs.readFileSync(SECRETS, 'utf8'));
  } catch {
    return {};
  }
}

function ecrireSecrets(secrets) {
  fs.mkdirSync(path.dirname(SECRETS), { recursive: true });
  const tmp = `${SECRETS}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(secrets, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, SECRETS);
}

function secondFacteurEnrole(identifiant) {
  const s = lireSecrets()[identifiant];
  return !!s && s.enrole === true;
}

/** Prépare un enrôlement. Le secret n'est confirmé qu'après un code valide. */
function preparerEnrolement(identifiant) {
  const secrets = lireSecrets();
  const secret = totp.nouveauSecret();
  secrets[identifiant] = { secret, enrole: false, prepare_le: new Date().toISOString() };
  ecrireSecrets(secrets);
  return { secret, uri: totp.uriEnrolement(secret, identifiant) };
}

/** Confirme l'enrôlement : le chercheur a produit un code depuis son application. */
function confirmerEnrolement(identifiant, code) {
  const secrets = lireSecrets();
  const s = secrets[identifiant];
  if (!s) throw new Error('aucun enrôlement en cours');

  const compteur = totp.verifier(s.secret, code, null);
  if (compteur === null) throw new Error('code incorrect');

  s.enrole = true;
  s.enrole_le = new Date().toISOString();
  s.dernier_compteur = compteur;
  ecrireSecrets(secrets);
  return true;
}

/**
 * Vérifie un code de second facteur.
 *
 * Le compteur validé est enregistré : un même code ne peut pas servir deux
 * fois. Sans cela, un code intercepté resterait utilisable jusqu'à la fin de
 * sa fenêtre.
 */
function verifierSecondFacteur(identifiant, code) {
  const secrets = lireSecrets();
  const s = secrets[identifiant];
  if (!s || !s.enrole) return false;

  const compteur = totp.verifier(s.secret, code, s.dernier_compteur ?? null);
  if (compteur === null) return false;

  s.dernier_compteur = compteur;
  ecrireSecrets(secrets);
  return true;
}

// ---------------------------------------------------------------------------
// Connexion
// ---------------------------------------------------------------------------

function verifierBlocage(identifiant) {
  const b = tentatives.get(identifiant);
  if (b && b.n >= TENTATIVES_MAX && Date.now() < b.jusqu_a) {
    const reste = Math.ceil((b.jusqu_a - Date.now()) / 60000);
    throw new Error(`trop de tentatives — réessayez dans ${reste} min`);
  }
}

function compterEchec(identifiant) {
  const b = tentatives.get(identifiant);
  const n = (b && Date.now() < b.jusqu_a ? b.n : 0) + 1;
  tentatives.set(identifiant, { n, jusqu_a: Date.now() + BLOCAGE_MS });
}

/**
 * Authentifie un chercheur.
 *
 * @returns {{etape: 'enrolement'|'connecte', ...}} `enrolement` quand le
 *   second facteur n'est pas encore posé : la première connexion l'impose.
 */
async function connecter(identifiant, motDePasse, code) {
  verifierBlocage(identifiant);

  const acces = lireRegistre()[identifiant];
  // Un accès qui n'est pas « actif » ne donne rien : provisionnement
  // interrompu, ou compte inconnu. Même message dans les deux cas.
  const utilisable = acces && acces.etat === 'actif' && acces.empreinte;
  const motDePasseValide = utilisable
    && await verifierMotDePasse(motDePasse, acces.empreinte);

  if (!motDePasseValide) {
    compterEchec(identifiant);
    throw new Error('identifiant ou mot de passe incorrect');
  }

  // Première connexion : le second facteur doit être enrôlé avant tout accès.
  if (!secondFacteurEnrole(identifiant)) {
    return { etape: 'enrolement', ...preparerEnrolement(identifiant) };
  }

  if (!verifierSecondFacteur(identifiant, code)) {
    compterEchec(identifiant);
    throw new Error('code de vérification incorrect');
  }

  tentatives.delete(identifiant);
  return { etape: 'connecte', jeton: signer({ identifiant, expire: Date.now() + DUREE_SESSION_MS }) };
}

// ---------------------------------------------------------------------------
// Jeton de session du portail
// ---------------------------------------------------------------------------

function signer(charge) {
  const corps = Buffer.from(JSON.stringify(charge)).toString('base64url');
  const sig = crypto.createHmac('sha256', SECRET_COOKIE).update(corps).digest('base64url');
  return `${corps}.${sig}`;
}

function verifierJeton(jeton) {
  if (typeof jeton !== 'string' || !jeton.includes('.')) return null;
  const [corps, sig] = jeton.split('.');
  const attendu = crypto.createHmac('sha256', SECRET_COOKIE).update(corps).digest('base64url');
  const a = Buffer.from(sig || '');
  const b = Buffer.from(attendu);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;

  let charge;
  try {
    charge = JSON.parse(Buffer.from(corps, 'base64url').toString('utf8'));
  } catch {
    return null;
  }
  if (!charge.expire || Date.now() > charge.expire) return null;
  return charge;
}

function lireCookie(req, nom) {
  for (const part of (req.headers.cookie || '').split(';')) {
    const [c, ...v] = part.trim().split('=');
    if (c === nom) return decodeURIComponent(v.join('='));
  }
  return null;
}

function garde(req, res, suite) {
  const charge = verifierJeton(lireCookie(req, 'enclave_portail'));
  if (!charge) return res.status(401).json({ erreur: 'session expirée ou absente' });
  if (req.method !== 'GET' && req.get('X-Portail') !== 'enclave') {
    return res.status(403).json({ erreur: 'en-tête de portail manquant' });
  }
  req.chercheur = charge;
  suite();
}

/**
 * Ouvre une session de portail pour un chercheur DEJA authentifie.
 *
 * Sert juste apres un enrolement : le mot de passe et le code viennent
 * d'etre verifies dans la meme requete. Revalider le code echouerait — et
 * c'est normal : l'anti-rejeu a deja consomme son compteur.
 */
function jetonPour(identifiant) {
  return signer({ identifiant, expire: Date.now() + DUREE_SESSION_MS });
}

module.exports = {
  connecter, garde, confirmerEnrolement, secondFacteurEnrole,
  lireRegistre, verifierMotDePasse, jetonPour, DUREE_SESSION_MS,
};
