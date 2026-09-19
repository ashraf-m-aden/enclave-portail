'use strict';
/**
 * =============================================================================
 *  PORTAIL CHERCHEUR — API
 *
 *  Seule surface exposée aux utilisateurs. Il ne détient PAS la clé de l'agent
 *  Samba : une compromission du portail ne permet ni de créer, ni de modifier,
 *  ni de révoquer un accès. Il lit le registre, il ne l'écrit pas.
 *
 *  Il écoute sur la boucle locale ; Nginx fait face au réseau.
 * =============================================================================
 */

const crypto = require('crypto');
const express = require('express');
const path = require('path');

const ORCHESTRATEUR = process.env.ORCHESTRATEUR_CHEMIN
  || '/opt/enclave/orchestrateur/services';
const session = require(path.join(ORCHESTRATEUR, 'session'));
const pve = require(path.join(ORCHESTRATEUR, 'proxmox'));

const auth = require('./auth');
const tickets = require('./reenrolement');
const surveillance = require('./surveillance');
const journal = require('./journal');

const app = express();
app.set('trust proxy', 'loopback');
app.use(express.json({ limit: '16kb' }));

app.use((req, res, suite) => {
  res.set('X-Content-Type-Options', 'nosniff');
  res.set('Cache-Control', 'no-store');
  suite();
});

const route = (fn) => (req, res) => {
  Promise.resolve(fn(req, res)).catch((e) => {
    journal.echec(req, `${req.method} ${req.path}`, e.message);
    if (!res.headersSent) res.status(500).json({ erreur: e.message });
  });
};

function poserCookie(res, jeton) {
  res.cookie('enclave_portail', jeton, {
    httpOnly: true, secure: true, sameSite: 'strict',
    maxAge: auth.DUREE_SESSION_MS, path: '/',
  });
}

// ---------------------------------------------------------------------------
// Ouvertures en cours
//
// `ouvrirSession` a besoin du mot de passe en clair pendant toute la création
// du clone — environ deux minutes : le compte Unix du clone en est dérivé, et
// `pam_mount` s'en sert pour monter les partages. Il est donc retenu en
// mémoire, et EFFACÉ dès que l'ouverture aboutit ou échoue.
//
// C'est un compromis assumé : le clair n'existe qu'en mémoire, jamais sur
// disque ni dans un journal, et pas plus longtemps que l'ouverture.
// ---------------------------------------------------------------------------

const ouvertures = new Map();   // ticket -> { identifiant, etat, url, erreur, debut }
const DELAI_ABANDON_MS = 10 * 60 * 1000;

function oublier(ticket) {
  const o = ouvertures.get(ticket);
  if (o) o.motDePasse = null;   // efface le clair sans attendre le nettoyage
}

setInterval(() => {
  const limite = Date.now() - DELAI_ABANDON_MS;
  for (const [t, o] of ouvertures) if (o.debut < limite) ouvertures.delete(t);
}, 60_000).unref();

function demarrerOuverture(identifiant, motDePasse, req) {
  const ticket = crypto.randomBytes(18).toString('base64url');
  const o = { identifiant, motDePasse, etat: 'en-cours', debut: Date.now() };
  ouvertures.set(ticket, o);

  session.ouvrirSession(identifiant, motDePasse)
    .then((r) => {
      o.etat = 'prete';
      // Guacamole est servi sous /guacamole/ ; le portail occupe la racine.
      o.url = `/guacamole/#/?token=${r.authToken}`;
      o.vmid = r.vmid;
      journal.ok(req, 'session-ouverte', { identifiant, vmid: r.vmid });
    })
    .catch((e) => {
      o.etat = 'echec';
      o.erreur = e.message;
      journal.echec(req, 'session-ouverte', e.message, { identifiant });
    })
    .finally(() => oublier(ticket));

  return ticket;
}

// ---------------------------------------------------------------------------
// Connexion
// ---------------------------------------------------------------------------

/**
 * Authentifie, puis lance l'ouverture de session.
 *
 * Trois réponses possibles :
 *   - `enrolement` : première connexion, le second facteur doit être posé ;
 *   - `session`    : authentifié, un ticket permet de suivre l'ouverture ;
 *   - une erreur.
 */
app.post('/api/connexion', route(async (req, res) => {
  const { identifiant, motDePasse, code, ticket } = req.body || {};
  if (!identifiant || !motDePasse) {
    return res.status(400).json({ erreur: 'identifiant et mot de passe requis' });
  }

  let r;
  try {
    r = await auth.connecter(String(identifiant).trim(), String(motDePasse), code, ticket);
  } catch (e) {
    journal.echec(req, 'connexion', e.message, { identifiant });
    return res.status(401).json({ erreur: e.message });
  }

  if (r.etape === 'enrolement') {
    journal.ok(req, r.reenrolement ? 'reenrolement-demande' : 'enrolement-demande', { identifiant });
    // Le secret n'est montré qu'à cet instant, pour être enrôlé.
    return res.json({
      etape: 'enrolement', secret: r.secret, uri: r.uri,
      reenrolement: r.reenrolement === true,
    });
  }

  poserCookie(res, r.jeton);
  journal.ok(req, 'connexion', { identifiant });
  res.json({
    etape: 'session',
    ticket: demarrerOuverture(String(identifiant).trim(), String(motDePasse), req),
  });
}));

/** Confirme l'enrôlement du second facteur, puis ouvre la session. */
app.post('/api/enrolement', route(async (req, res) => {
  const { identifiant, motDePasse, code, ticket } = req.body || {};
  if (!identifiant || !motDePasse || !code) {
    return res.status(400).json({ erreur: 'identifiant, mot de passe et code requis' });
  }

  // On revérifie le mot de passe : sans cela, quiconque connaît un identifiant
  // en cours d'enrôlement pourrait y poser SON propre second facteur.
  const acces = auth.lireRegistre()[identifiant];
  const valide = acces && acces.etat === 'actif' && acces.empreinte
    && await auth.verifierMotDePasse(String(motDePasse), acces.empreinte);
  if (!valide) {
    journal.echec(req, 'enrolement', 'mot de passe invalide', { identifiant });
    return res.status(401).json({ erreur: 'identifiant ou mot de passe incorrect' });
  }

  // Réenrôlement : le ticket est revérifié ICI aussi. Sans cela, un appel
  // direct à cette route sauterait le contrôle fait à la connexion.
  const reenrolement = auth.reenrolementRequis(identifiant);
  if (reenrolement && !tickets.valide(identifiant, ticket)) {
    journal.echec(req, 'reenrolement', 'ticket absent, expiré ou incorrect', { identifiant });
    return res.status(401).json({ erreur: 'ticket de réenrôlement absent, expiré ou incorrect' });
  }

  try {
    auth.confirmerEnrolement(identifiant, String(code));
  } catch (e) {
    journal.echec(req, 'enrolement', e.message, { identifiant });
    return res.status(401).json({ erreur: e.message });
  }

  // Le mot de passe et le code viennent d'etre verifies ci-dessus. Repasser
  // par connecter() echouerait : l'anti-rejeu a consomme le compteur de ce
  // code, et c'est exactement ce qu'on attend de lui.
  // Le ticket a servi : il ne resservira pas.
  if (reenrolement) tickets.consommer(identifiant);

  poserCookie(res, auth.jetonPour(identifiant));
  journal.ok(req, reenrolement ? 'reenrolement' : 'enrolement', { identifiant });
  res.json({
    etape: 'session',
    ticket: demarrerOuverture(identifiant, String(motDePasse), req),
  });
}));

// ---------------------------------------------------------------------------
// Suivi de l'ouverture
// ---------------------------------------------------------------------------

app.get('/api/session/:ticket', auth.garde, route(async (req, res) => {
  const o = ouvertures.get(req.params.ticket);
  if (!o) return res.status(404).json({ erreur: 'ouverture inconnue ou expirée' });
  // Un ticket n'appartient qu'à son chercheur.
  if (o.identifiant !== req.chercheur.identifiant) {
    return res.status(403).json({ erreur: 'ticket refusé' });
  }

  res.json({
    etat: o.etat,
    url: o.url || null,
    erreur: o.erreur || null,
    secondes: Math.round((Date.now() - o.debut) / 1000),
  });
}));

app.get('/api/moi', auth.garde, route(async (req, res) => {
  res.json({ chercheur: { identifiant: req.chercheur.identifiant } });
}));

app.post('/api/deconnexion', auth.garde, route(async (req, res) => {
  journal.ok(req, 'deconnexion', { identifiant: req.chercheur.identifiant });
  res.clearCookie('enclave_portail', { path: '/' });
  res.json({ ok: true });
}));

// ---------------------------------------------------------------------------
// Route INTERNE — réservée à la console d'administration
//
// Elle vit sous /interne/, que Nginx ne proxifie PAS : seul un service du
// réseau Docker peut l'atteindre. Un secret partagé s'ajoute à cette
// isolation réseau, pour que l'un ne repose pas sur l'autre.
//
// Elle ne permet QUE d'invalider un enrôlement. Jamais de lire un secret,
// jamais d'en définir un : le secret TOTP reste du seul ressort du portail.
// ---------------------------------------------------------------------------

const SECRET_INTERNE = process.env.INTERNE_SECRET || '';

function gardeInterne(req, res, suite) {
  if (!SECRET_INTERNE) {
    return res.status(503).json({ erreur: 'route interne non configurée' });
  }
  const propose = Buffer.from(req.get('X-Interne') || '');
  const attendu = Buffer.from(SECRET_INTERNE);
  if (propose.length !== attendu.length || !crypto.timingSafeEqual(propose, attendu)) {
    return res.status(403).json({ erreur: 'secret interne incorrect' });
  }
  suite();
}

/**
 * Révoque le second facteur et rend un ticket de réenrôlement.
 *
 * La console reçoit le ticket — qu'elle transmet au chercheur hors bande —
 * mais jamais le secret TOTP, ni avant ni après.
 */
app.post('/interne/reenrolement', gardeInterne, route(async (req, res) => {
  const { identifiant, demandePar, approuvePar } = req.body || {};
  if (!identifiant || !demandePar) {
    return res.status(400).json({ erreur: 'identifiant et demandeur requis' });
  }

  let ticket;
  try {
    ticket = auth.revoquerEnrolement(String(identifiant), { demandePar, approuvePar });
  } catch (e) {
    journal.echec(req, 'revocation-second-facteur', e.message, { identifiant });
    return res.status(409).json({ erreur: e.message });
  }

  journal.ok(req, 'revocation-second-facteur', {
    identifiant, demande_par: demandePar, approuve_par: approuvePar || null,
    expire_le: ticket.expire_le,
  });

  res.json({
    ticket: ticket.identifiant,
    expire_le: ticket.expire_le,
    validite_minutes: Math.round(tickets.VALIDITE_MS / 60000),
  });
}));

/** État du ticket d'un chercheur. Ne révèle jamais sa valeur. */
app.get('/interne/reenrolement/:identifiant', gardeInterne, route(async (req, res) => {
  res.json({ ticket: tickets.etat(req.params.identifiant) });
}));

// ---------------------------------------------------------------------------

/** État de la surveillance, pour le tableau de bord de la console. */
app.get('/interne/surveillance', gardeInterne, route(async (req, res) => {
  res.json({
    sessions: surveillance.etatDesSessions(),
    reglages: {
      inactivite_min: Math.round(surveillance.INACTIVITE_MS / 60000),
      accueil_min: Math.round(surveillance.ACCUEIL_MS / 60000),
      duree_max_h: Math.round(surveillance.DUREE_MAX_MS / 3600000),
      seuil_octets_min: surveillance.SEUIL_OCTETS_PAR_MIN,
      demarrage_min: Math.round(surveillance.DELAI_DEMARRAGE_MS / 60000),
    },
  });
}));

app.use((req, res) => res.status(404).json({ erreur: 'route inconnue' }));

const PORT = parseInt(process.env.PORTAIL_PORT || '8091', 10);
const HOTE = process.env.PORTAIL_HOTE || '127.0.0.1';

if (require.main === module) {
  app.listen(PORT, HOTE, () => console.log(`[portail] portail chercheur sur http://${HOTE}:${PORT}`));
  // Détruit les clones dont personne ne se sert : déconnexion, session laissée
  // ouverte, ou machine créée puis jamais utilisée.
  surveillance.demarrer(pve, session.fermerSession, journal);
}

module.exports = app;
