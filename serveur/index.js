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
// UN seul saut de confiance : Nginx, et rien d'autre.
//
// « loopback » ne suffit PAS ici. Nginx tourne sur l'hote et joint
// 127.0.0.1:8091 ; Docker redirige vers le conteneur, qui voit alors comme
// source la passerelle du pont (172.20.0.1), pas une adresse de bouclage.
// Express refusait donc l'en-tete X-Forwarded-For, et TOUTES les entrees du
// journal portaient « 172.20.0.1 » au lieu de l'adresse du chercheur : un
// journal d'audit incapable de tracer qui s'est connecte d'ou.
//
// « 1 » n'est sur QUE parce que le port du conteneur est publie sur
// 127.0.0.1 uniquement (voir docker-compose.yml) : Nginx est le seul client
// possible, personne ne peut forger l'en-tete. Republier ce port sur 0.0.0.0
// rendrait l'adresse falsifiable.
//
// Un relais SUPPLEMENTAIRE en amont (repartiteur de charge, CDN) ferait deux
// sauts : il faudrait alors passer cette valeur a 2, sans quoi c'est l'adresse
// du relais qui serait journalisee.
app.set('trust proxy', 1);
app.use(express.json({ limit: '16kb' }));

// L'interface est servie DEPUIS LE CONTENEUR, avec le code qui la sert : une
// seule copie, qui ne peut pas diverger de l'API.
const INTERFACE = process.env.INTERFACE_CHEMIN || path.join(__dirname, 'console');

app.use((req, res, suite) => {
  res.set('X-Content-Type-Options', 'nosniff');
  if (req.path.startsWith('/api/')) res.set('Cache-Control', 'no-store');
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
      o.reprise = r.reprise === true;
      // Le chercheur est revenu : le compte a rebours de grace tombe, sinon
      // la surveillance detruirait la session qu'on vient de lui rendre.
      if (r.reprise) surveillance.signalerReconnexion(r.vmid);
      journal.ok(req, r.reprise ? 'session-reprise' : 'session-ouverte',
        { identifiant, vmid: r.vmid });
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
    r = await auth.connecter(
      String(identifiant).trim(), String(motDePasse), code, ticket, req.ip,
    );
  } catch (e) {
    journal.echec(req, 'connexion', e.message, { identifiant });
    // Attaque repartie : beaucoup d'echecs sur un meme compte, depuis des
    // adresses differentes. Rien n'est bloque — bloquer globalement rendrait
    // possible le verrouillage d'un chercheur par un tiers — mais la console
    // doit le voir.
    if (e.alerteForceBrute) {
      journal.echec(req, 'alerte-force-brute', "seuil d'echecs franchi", {
        identifiant, echecs: e.alerteForceBrute,
      });
    }
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
    // Le vmid est celui de SA session — derive de son identifiant, jamais
    // fourni par lui. Aucune route ne prend un vmid en entree cote chercheur.
    vmid: o.vmid ?? null,
    // Permet a l'interface de dire « nous avons retrouve votre session »
    // plutot que de laisser croire a un redemarrage.
    reprise: o.reprise === true,
  });
}));

app.get('/api/moi', auth.garde, route(async (req, res) => {
  res.json({ chercheur: { identifiant: req.chercheur.identifiant } });
}));

/**
 * Deconnexion VOULUE : le chercheur a clique sur « terminer ma session ».
 *
 * L'intention est explicite, donc pas de delai de grace — contrairement a la
 * fermeture d'onglet, qui peut n'etre qu'une coupure reseau.
 *
 * On MARQUE la session ; c'est le passage de surveillance qui detruit. Un seul
 * chemin de destruction, journalise et testable.
 */
app.post('/api/deconnexion', auth.garde, route(async (req, res) => {
  const identifiant = req.chercheur.identifiant;
  let vmid = null;
  try {
    const s = await session.sessionExistante(identifiant);
    if (s) {
      vmid = s.vmid;
      surveillance.signalerDeconnexion(vmid, true);
    }
  } catch (e) {
    // Proxmox injoignable : la deconnexion du portail doit aboutir quand meme.
    // Le ramassage par inactivite reste le filet.
    console.warn(`[deconnexion] ${identifiant} : ${e.message}`);
  }
  journal.ok(req, 'deconnexion', { identifiant, vmid, fermeture: vmid ? 'demandee' : 'aucune session' });
  res.clearCookie('enclave_portail', { path: '/' });
  res.json({ ok: true, vmid });
}));

/**
 * Le navigateur signale que le chercheur a quitte la page de session.
 *
 * Utilise gardeSignal et NON garde : sendBeacon ne peut poser AUCUN en-tete
 * personnalise, donc pas de X-Portail. Avec la garde normale, le signal
 * partait du navigateur et se faisait rejeter en 403 — la fonction n'aurait
 * jamais marche en vrai. La protection CSRF vient du cookie SameSite=Strict.
 *
 * Appele par sendBeacon a la fermeture de l'onglet : la requete part meme si
 * la page dispararait dans la foulee. Le corps est envoye en text/plain —
 * sendBeacon ne permet pas de poser un en-tete Content-Type arbitraire sans
 * declencher un preflight CORS.
 *
 * ON NE DETRUIT PAS ICI. Une coupure reseau de vingt secondes produit le meme
 * signal qu'un depart definitif : la surveillance attend le delai de grace, et
 * une reconnexion pendant ce delai annule le compte a rebours et rend au
 * chercheur SA session, RStudio ouvert.
 */
app.post('/api/session/quittee', auth.gardeSignal, route(async (req, res) => {
  const identifiant = req.chercheur.identifiant;
  // Reponse immediate : le navigateur est peut-etre deja en train de fermer.
  res.status(204).end();
  try {
    const s = await session.sessionExistante(identifiant);
    if (s && surveillance.signalerDeconnexion(s.vmid, false)) {
      journal.ecrire({ action: 'session-quittee', identifiant, vmid: s.vmid, resultat: 'ok' });
    }
  } catch (e) {
    console.warn(`[session-quittee] ${identifiant} : ${e.message}`);
  }
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
/**
 * Efface le second facteur d'un compte dont l'ACCES vient d'etre revoque.
 *
 * Appelee par la console apres une suppression d'acces reussie. Sans elle, le
 * secret TOTP survivait a l'acces : un identifiant recree plus tard arrivait
 * DEJA enrole, avec le secret de l'ancien titulaire. Le nouveau chercheur ne
 * pouvait pas se connecter, et l'ancien conservait un facteur valide.
 *
 * Idempotente : rien a effacer n'est pas une erreur. La console ne doit pas
 * echouer une revocation parce que le chercheur ne s'etait jamais enrole.
 */
app.delete('/interne/second-facteur/:identifiant', gardeInterne, route(async (req, res) => {
  const identifiant = String(req.params.identifiant);
  const efface = auth.purgerSecondFacteur(identifiant);
  tickets.consommer(identifiant);
  if (efface) {
    journal.ok(req, 'purge-second-facteur', { identifiant });
  }
  res.json({ ok: true, efface });
}));

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

// --- Interface ---------------------------------------------------------------

app.use('/assets', express.static(path.join(INTERFACE, 'assets'), {
  immutable: true,
  maxAge: '1y',
}));

app.use(express.static(INTERFACE, { index: false }));

app.use((req, res, suite) => {
  if (req.path.startsWith('/api/') || req.path.startsWith('/interne/')) return suite();
  res.sendFile(path.join(INTERFACE, 'index.html'), (e) => { if (e) suite(); });
});

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
