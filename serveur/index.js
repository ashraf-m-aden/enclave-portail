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

const auth = require('./auth');
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
  const { identifiant, motDePasse, code } = req.body || {};
  if (!identifiant || !motDePasse) {
    return res.status(400).json({ erreur: 'identifiant et mot de passe requis' });
  }

  let r;
  try {
    r = await auth.connecter(String(identifiant).trim(), String(motDePasse), code);
  } catch (e) {
    journal.echec(req, 'connexion', e.message, { identifiant });
    return res.status(401).json({ erreur: e.message });
  }

  if (r.etape === 'enrolement') {
    journal.ok(req, 'enrolement-demande', { identifiant });
    // Le secret n'est montré qu'à cet instant, pour être enrôlé.
    return res.json({ etape: 'enrolement', secret: r.secret, uri: r.uri });
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
  const { identifiant, motDePasse, code } = req.body || {};
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

  try {
    auth.confirmerEnrolement(identifiant, String(code));
  } catch (e) {
    journal.echec(req, 'enrolement', e.message, { identifiant });
    return res.status(401).json({ erreur: e.message });
  }

  // Le mot de passe et le code viennent d'etre verifies ci-dessus. Repasser
  // par connecter() echouerait : l'anti-rejeu a consomme le compteur de ce
  // code, et c'est exactement ce qu'on attend de lui.
  poserCookie(res, auth.jetonPour(identifiant));
  journal.ok(req, 'enrolement', { identifiant });
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

app.use((req, res) => res.status(404).json({ erreur: 'route inconnue' }));

const PORT = parseInt(process.env.PORTAIL_PORT || '8091', 10);
const HOTE = process.env.PORTAIL_HOTE || '127.0.0.1';

if (require.main === module) {
  app.listen(PORT, HOTE, () => console.log(`[portail] portail chercheur sur http://${HOTE}:${PORT}`));
}

module.exports = app;
