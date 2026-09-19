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
const tickets = require('./reenrolement');

const REGISTRE = process.env.ENCLAVE_ETAT
  || '/opt/enclave/orchestrateur/etat/acces.json';
const SECRETS = process.env.PORTAIL_SECRETS
  || path.join(__dirname, 'etat', 'second-facteur.json');

const DUREE_SESSION_MS = 30 * 60 * 1000;   // le temps d'ouvrir une session
// Blocage precis : 5 echecs pour UN couple (identifiant, adresse).
const TENTATIVES_MAX = 5;
const BLOCAGE_MS = 15 * 60 * 1000;

// Seuil d'ALERTE, tous couples confondus pour un meme identifiant. Il ne
// bloque rien : il laisse une trace au journal. Voir plus bas pourquoi.
const SEUIL_ALERTE = 20;
const FENETRE_ALERTE_MS = 15 * 60 * 1000;

const SECRET_COOKIE = process.env.PORTAIL_SECRET
  || crypto.randomBytes(32).toString('hex');

// Cle : "identifiant|adresse". Deux cartes distinctes, deux roles distincts.
const tentatives = new Map();
// Cle : identifiant seul. Sert uniquement a reperer une attaque repartie.
const echecsParCompte = new Map();

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
  // CONSERVER le drapeau `revoque`. L'écraser ferait perdre la trace du
  // réenrôlement en cours : /api/enrolement n'exigerait plus le ticket, et
  // le mot de passe seul suffirait à poser un nouveau second facteur —
  // exactement la fenêtre que le ticket doit fermer.
  const revoque = secrets[identifiant] && secrets[identifiant].revoque === true;
  secrets[identifiant] = {
    secret,
    enrole: false,
    ...(revoque ? { revoque: true } : {}),
    prepare_le: new Date().toISOString(),
  };
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
  delete s.revoque;      // le réenrôlement est abouti
  ecrireSecrets(secrets);
  return true;
}

/**
 * Révoque l'enrôlement d'un chercheur et émet un ticket de réenrôlement.
 *
 * Appelée UNIQUEMENT par la route interne, elle-même réservée à la console.
 * Elle n'expose jamais le secret : elle l'efface et rend un ticket. La route
 * exposée ne permet donc que d'invalider — jamais de lire ni de définir.
 */
function revoquerEnrolement(identifiant, { demandePar, approuvePar }) {
  const secrets = lireSecrets();
  if (!secrets[identifiant] || !secrets[identifiant].enrole) {
    throw new Error("aucun second facteur enrôlé pour ce compte");
  }

  // Le secret est détruit, pas conservé « au cas où » : un secret révoqué qui
  // traîne est un secret qui peut resservir.
  secrets[identifiant] = {
    enrole: false,
    revoque: true,
    revoque_le: new Date().toISOString(),
  };
  ecrireSecrets(secrets);

  return tickets.emettre(identifiant, { demandePar, approuvePar });
}

/**
 * Efface TOUTE trace du second facteur d'un compte.
 *
 * A n'appeler QUE lorsque l'acces lui-meme est revoque : la personne s'en va,
 * rien ne doit lui survivre.
 *
 * A NE PAS CONFONDRE avec revoquerEnrolement(), qui garde une marque
 * « revoque » pour EXIGER un ticket au prochain enrolement. Cette marque est
 * juste tant que le compte existe ; elle devient nuisible quand il disparait,
 * car un identifiant recree heriterait d'une exigence de ticket que personne
 * ne lui a remis.
 *
 * POURQUOI CETTE FONCTION EXISTE. Supprimer un acces ne touchait pas au
 * second facteur. Recreer plus tard le meme identifiant donnait un compte
 * DEJA enrole, avec le secret de l'ancien titulaire : le nouveau chercheur ne
 * pouvait pas se connecter, et l'ancien gardait un facteur valide. Constate en
 * rejouant un essai de bout en bout sur un identifiant reutilise.
 *
 * @returns {boolean} vrai si quelque chose a ete efface.
 */
function purgerSecondFacteur(identifiant) {
  const secrets = lireSecrets();
  if (!(identifiant in secrets)) return false;
  delete secrets[identifiant];
  ecrireSecrets(secrets);
  return true;
}

/** Un réenrôlement est-il en attente pour ce compte ? */
function reenrolementRequis(identifiant) {
  const s = lireSecrets()[identifiant];
  return !!s && s.revoque === true && s.enrole !== true;
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

/**
 * Clé de blocage : l'identifiant ET l'adresse d'où vient la tentative.
 *
 * POURQUOI PAS L'IDENTIFIANT SEUL. Un compteur porté par le seul identifiant
 * laisse n'importe qui verrouiller n'importe quel chercheur : cinq erreurs
 * volontaires sur son nom, et il ne peut plus travailler pendant quinze
 * minutes. C'est un déni de service gratuit contre une personne nommée.
 *
 * POURQUOI PAS L'ADRESSE SEULE. Une université partenaire peut présenter une
 * seule adresse publique pour tous ses chercheurs : le premier qui se trompe
 * bloquerait ses collègues.
 *
 * Le couple règle les deux : celui qui se trompe se bloque lui-même, et
 * personne d'autre.
 */
function cleBlocage(identifiant, adresse) {
  return `${identifiant}|${adresse || 'inconnue'}`;
}

function verifierBlocage(identifiant, adresse) {
  const b = tentatives.get(cleBlocage(identifiant, adresse));
  if (b && b.n >= TENTATIVES_MAX && Date.now() < b.jusqu_a) {
    const reste = Math.ceil((b.jusqu_a - Date.now()) / 60000);
    throw new Error(`trop de tentatives — réessayez dans ${reste} min`);
  }
}

/**
 * Enregistre un échec, et renvoie une alerte quand un même compte est attaqué
 * depuis de nombreuses adresses.
 *
 * Le couple (identifiant, adresse) ferme le déni de service, mais rouvre une
 * porte : un attaquant disposant de mille adresses obtient cinq essais sur
 * chacune. On ne peut pas bloquer globalement sans rétablir le déni de
 * service — alors on ne bloque pas, ON VOIT. L'alerte part au journal, que la
 * console affiche, et un administrateur décide.
 *
 * Ce choix se tient parce que le mot de passe ne suffit jamais : le second
 * facteur reste devant. Une attaque par dictionnaire réussie ne donne encore
 * rien.
 *
 * @returns {number|null} nombre d'échecs sur la fenêtre si le seuil d'alerte
 *   vient d'être franchi, sinon null.
 */
function compterEchec(identifiant, adresse) {
  const maintenant = Date.now();

  const cle = cleBlocage(identifiant, adresse);
  const b = tentatives.get(cle);
  const n = (b && maintenant < b.jusqu_a ? b.n : 0) + 1;
  tentatives.set(cle, { n, jusqu_a: maintenant + BLOCAGE_MS });

  const g = echecsParCompte.get(identifiant);
  const dansLaFenetre = g && maintenant < g.jusqu_a;
  const total = (dansLaFenetre ? g.n : 0) + 1;
  const dejaSignale = dansLaFenetre ? g.signale : false;
  echecsParCompte.set(identifiant, {
    n: total,
    jusqu_a: dansLaFenetre ? g.jusqu_a : maintenant + FENETRE_ALERTE_MS,
    signale: dejaSignale || total >= SEUIL_ALERTE,
  });

  purger(maintenant);
  // Une seule alerte par fenêtre : on signale au franchissement, pas à chaque
  // échec suivant, sinon le journal devient illisible au pire moment.
  return (total >= SEUIL_ALERTE && !dejaSignale) ? total : null;
}

/**
 * Retire les entrées expirées. Sans cela, les deux cartes grossissent à
 * chaque identifiant essayé : une pulvérisation sur un dictionnaire de noms
 * les ferait enfler sans limite, et c'est la mémoire du portail qui cèderait.
 */
function purger(maintenant) {
  for (const [cle, v] of tentatives) {
    if (maintenant >= v.jusqu_a) tentatives.delete(cle);
  }
  for (const [cle, v] of echecsParCompte) {
    if (maintenant >= v.jusqu_a) echecsParCompte.delete(cle);
  }
}

/**
 * Authentifie un chercheur.
 *
 * @returns {{etape: 'enrolement'|'connecte', ...}} `enrolement` quand le
 *   second facteur n'est pas encore posé : la première connexion l'impose.
 */
async function connecter(identifiant, motDePasse, code, ticket, adresse) {
  verifierBlocage(identifiant, adresse);
  // Rempli quand une attaque repartie franchit le seuil : l'appelant le
  // porte au journal. Une valeur, pas une ecriture directe — auth.js ne
  // connait pas la requete HTTP.
  let alerte = null;

  const acces = lireRegistre()[identifiant];
  // Un accès qui n'est pas « actif » ne donne rien : provisionnement
  // interrompu, ou compte inconnu. Même message dans les deux cas.
  const utilisable = acces && acces.etat === 'actif' && acces.empreinte;
  const motDePasseValide = utilisable
    && await verifierMotDePasse(motDePasse, acces.empreinte);

  if (!motDePasseValide) {
    alerte = compterEchec(identifiant, adresse);
    const e = new Error('identifiant ou mot de passe incorrect');
    e.alerteForceBrute = alerte;
    throw e;
  }

  // Réenrôlement après révocation : le mot de passe NE SUFFIT PAS. Il faut
  // aussi le ticket, qui expire. C'est ce qui borne la fenêtre pendant
  // laquelle le compte serait réduit à un seul facteur.
  if (reenrolementRequis(identifiant)) {
    if (!tickets.valide(identifiant, ticket)) {
      const e = new Error('ticket de réenrôlement absent, expiré ou incorrect');
      e.alerteForceBrute = compterEchec(identifiant, adresse);
      throw e;
    }
    return { etape: 'enrolement', reenrolement: true, ...preparerEnrolement(identifiant) };
  }

  // Première connexion : le second facteur doit être enrôlé avant tout accès.
  if (!secondFacteurEnrole(identifiant)) {
    return { etape: 'enrolement', reenrolement: false, ...preparerEnrolement(identifiant) };
  }

  if (!verifierSecondFacteur(identifiant, code)) {
    const e = new Error('code de vérification incorrect');
    e.alerteForceBrute = compterEchec(identifiant, adresse);
    throw e;
  }

  // Connexion reussie : on efface le compteur de CE couple seulement. Les
  // echecs venus d'ailleurs restent comptes — une reussite legitime ne doit
  // pas blanchir une attaque en cours depuis une autre adresse.
  tentatives.delete(cleBlocage(identifiant, adresse));
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

/**
 * Garde allegee pour le signal de fermeture d'onglet.
 *
 * Verifie le cookie, mais PAS l'en-tete X-Portail — parce que
 * navigator.sendBeacon NE PEUT PAS poser d'en-tete personnalise. Avec la
 * garde normale, le signal partait bel et bien du navigateur et se faisait
 * rejeter en 403 : la fonction n'aurait jamais marche en vrai, sans que rien
 * ne le montre. Trouve en rejouant le parcours complet cote serveur.
 *
 * La protection CSRF reste entiere : le cookie est en SameSite=Strict, donc
 * une requete venue d'un autre site ne le porte pas du tout et echoue des la
 * verification du jeton. L'en-tete n'etait qu'une seconde ceinture.
 *
 * Cette garde ne protege QU'UNE route, qui ne fait que marquer une session
 * pour un compte a rebours de dix minutes — et qu'une reconnexion annule.
 */
function gardeSignal(req, res, suite) {
  const charge = verifierJeton(lireCookie(req, 'enclave_portail'));
  if (!charge) return res.status(401).json({ erreur: 'session expirée ou absente' });
  req.chercheur = charge;
  suite();
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
  revoquerEnrolement, purgerSecondFacteur, gardeSignal, reenrolementRequis,
  lireRegistre, verifierMotDePasse, jetonPour, DUREE_SESSION_MS,
};
