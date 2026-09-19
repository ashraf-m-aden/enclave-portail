'use strict';
/**
 * =============================================================================
 *  PORTAIL — surveillance des sessions
 *
 *  LE PROBLÈME QU'ELLE RÉSOUT. Rien ne détruisait un clone à la déconnexion :
 *  un chercheur qui fermait son navigateur laissait sa machine allumée, et sa
 *  reconnexion en créait une seconde. Les clones s'accumulaient jusqu'à saturer
 *  la mémoire et le stockage.
 *
 *  COMMENT ON DÉTECTE. Sans donner à l'orchestrateur le droit d'exécuter des
 *  commandes dans l'invité — privilège refusé en § 12 — le seul signal
 *  observable est le **compteur d'octets émis par la VM**, que l'API Proxmox
 *  expose avec `VM.Audit`. Une session RDP ouverte produit un flux continu ;
 *  une machine dont personne n'est connecté n'émet presque rien.
 *
 *  Trois règles, dans cet ordre :
 *
 *    1. ABANDON      — créée, jamais utilisée, au-delà du délai d'accueil.
 *    2. INACTIVITÉ   — plus d'activité depuis le délai configuré (30 min).
 *    3. DURÉE MAXIMALE — au-delà, la session est fermée quoi qu'il arrive.
 *
 *  Toute destruction est journalisée avec son motif : un chercheur qui trouve
 *  sa session fermée doit pouvoir savoir pourquoi.
 * =============================================================================
 */

const fs = require('fs');
const path = require('path');

const ETAT = process.env.PORTAIL_SURVEILLANCE
  || path.join(__dirname, 'etat', 'surveillance.json');

/** Débit en dessous duquel on considère que personne n'est connecté.
 *  Une session RDP, même sans frappe, dépasse largement ce seuil ; une VM
 *  sans connexion se limite à quelques trames SMB. */
const SEUIL_OCTETS_PAR_MIN = parseInt(process.env.SEUIL_ACTIVITE || '20480', 10);

const INTERVALLE_MS = parseInt(process.env.SURVEILLANCE_INTERVALLE || '60000', 10);
const INACTIVITE_MS = parseInt(process.env.INACTIVITE_MAX || String(30 * 60 * 1000), 10);
/** Temps laissé au chercheur pour se connecter, À COMPTER DU MOMENT OÙ LA
 *  SESSION EST PRÊTE — pas du démarrage de la VM. La création prend environ
 *  deux minutes et demie : compter depuis le démarrage reviendrait à fermer
 *  la session avant que le chercheur ait pu s'y connecter. */
const ACCUEIL_MS = parseInt(process.env.DELAI_ACCUEIL || String(15 * 60 * 1000), 10);
/** Marge avant que la surveillance ne juge un clone : le temps que xrdp
 *  écoute et que le chercheur soit redirigé. */
const DELAI_DEMARRAGE_MS = parseInt(process.env.DELAI_DEMARRAGE || String(4 * 60 * 1000), 10);
/** Garde-fou absolu : une session ne dure pas indéfiniment. */
const DUREE_MAX_MS = parseInt(process.env.DUREE_MAX_SESSION || String(12 * 60 * 60 * 1000), 10);

// Delai de grace apres une deconnexion SIGNALEE par le navigateur du
// chercheur — a distinguer de l'inactivite mesuree, qui est une deduction.
//
// POURQUOI UN DELAI, ET PAS UNE DESTRUCTION IMMEDIATE. Une coupure reseau de
// vingt secondes produit exactement le meme signal qu'une fermeture
// volontaire. Detruire aussitot effacerait les tampons non enregistres de
// RStudio sur un simple hoquet. Les fichiers de « travaux » sont a l'abri —
// ils vivent sur le serveur de fichiers — mais pas un script en cours
// d'ecriture.
//
// Pendant ce delai, une reconnexion RETROUVE la meme VM : voir la reprise de
// session dans session.js.
const GRACE_DECONNEXION_MS = parseInt(
  process.env.GRACE_DECONNEXION || String(10 * 60 * 1000), 10);

function lire() {
  try {
    return JSON.parse(fs.readFileSync(ETAT, 'utf8'));
  } catch {
    return {};
  }
}

function ecrire(etat) {
  fs.mkdirSync(path.dirname(ETAT), { recursive: true });
  const tmp = `${ETAT}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(etat, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, ETAT);
}

/**
 * Le navigateur du chercheur signale une deconnexion.
 *
 * On MARQUE, on ne detruit pas : la destruction reste au seul passage de
 * surveillance. Un unique chemin de destruction se raisonne, se journalise et
 * se teste ; deux chemins concurrents finissent toujours par se marcher dessus.
 *
 * @param {number} vmid
 * @param {boolean} immediat  true pour une deconnexion VOULUE (bouton), qui
 *   n'a pas besoin de delai de grace : l'intention est explicite.
 */
function signalerDeconnexion(vmid, immediat = false) {
  const suivi = lire();
  const s = suivi[String(vmid)];
  if (!s) return false;
  s.deconnecte_le = immediat ? 0 : Date.now();
  s.deconnexion_voulue = !!immediat;
  ecrire(suivi);
  return true;
}

/** Le chercheur est revenu : la session reprend, le compte a rebours tombe. */
function signalerReconnexion(vmid) {
  const suivi = lire();
  const s = suivi[String(vmid)];
  if (!s) return false;
  delete s.deconnecte_le;
  delete s.deconnexion_voulue;
  s.derniereActivite = Date.now();
  s.dejaActive = true;
  ecrire(suivi);
  return true;
}

/** Ce que la surveillance sait de chaque clone, pour la console. */
function etatDesSessions() {
  const suivi = lire();
  const maintenant = Date.now();
  return Object.entries(suivi).map(([vmid, s]) => ({
    vmid: parseInt(vmid, 10),
    ouverte_le: new Date(s.creation).toISOString(),
    duree_s: Math.round((maintenant - s.creation) / 1000),
    active: !!s.dejaActive,
    derniere_activite_s: s.derniereActivite
      ? Math.round((maintenant - s.derniereActivite) / 1000)
      : null,
    debit_octets_min: s.debit ?? null,
    deconnecte_depuis_s: s.deconnecte_le
      ? Math.round((maintenant - s.deconnecte_le) / 1000)
      : null,
  }));
}

/**
 * Un passage de surveillance.
 *
 * @param {object} pve     client Proxmox
 * @param {Function} fermer  fermeture d'une session (arrêt, destruction, snippet)
 * @param {object} journal
 */
async function passage(pve, fermer, journal) {
  let clones;
  try {
    clones = await pve.listerClones();
  } catch (e) {
    console.warn(`[surveillance] Proxmox injoignable : ${e.message}`);
    return [];
  }

  const suivi = lire();
  const maintenant = Date.now();
  const fermees = [];
  const vivants = new Set();

  for (const c of clones) {
    const vmid = String(c.vmid);
    vivants.add(vmid);

    // Un clone arrêté mais non détruit est un résidu : on le nettoie.
    if (c.status !== 'running') {
      fermees.push({ vmid: c.vmid, motif: 'clone arrêté' });
      continue;
    }

    const octets = (c.netout || 0) + (c.netin || 0);
    let s = suivi[vmid];

    if (!s) {
      // Première observation : on ne peut pas encore mesurer un débit.
      suivi[vmid] = {
        creation: maintenant - (c.uptime || 0) * 1000,
        octets,
        derniereMesure: maintenant,
        derniereActivite: null,
        dejaActive: false,
      };
      continue;
    }

    const minutes = Math.max((maintenant - s.derniereMesure) / 60000, 0.1);
    const debit = Math.round((octets - s.octets) / minutes);
    s.debit = debit;
    s.octets = octets;
    s.derniereMesure = maintenant;

    if (debit >= SEUIL_OCTETS_PAR_MIN) {
      s.derniereActivite = maintenant;
      s.dejaActive = true;
    }

    // Un clone encore en cours de création n'est pas jugé : il n'émet rien
    // tant que cloud-init tourne et que xrdp n'écoute pas.
    if (maintenant - s.creation < DELAI_DEMARRAGE_MS) continue;

    // --- Règle 1 : créée, jamais utilisée -----------------------------------
    if (!s.dejaActive && maintenant - s.creation > DELAI_DEMARRAGE_MS + ACCUEIL_MS) {
      fermees.push({ vmid: c.vmid, motif: 'jamais utilisée' });
      continue;
    }

    // --- Règle 2 : déconnexion signalée --------------------------------------
    // Un SIGNAL, pas une déduction : le navigateur a dit que le chercheur
    // était parti. On peut donc être bien plus rapide que la règle 3, qui doit
    // rester tolérante pour ne pas fermer la session de quelqu'un qui réfléchit
    // devant son écran sans toucher au clavier.
    if (s.deconnecte_le !== undefined
        && maintenant - s.deconnecte_le > (s.deconnexion_voulue ? 0 : GRACE_DECONNEXION_MS)) {
      fermees.push({
        vmid: c.vmid,
        motif: s.deconnexion_voulue
          ? 'déconnexion demandée par le chercheur'
          : `déconnecté depuis ${Math.round((maintenant - s.deconnecte_le) / 60000)} min`,
      });
      continue;
    }

    // --- Règle 3 : inactivité ------------------------------------------------
    // Couvre la déconnexion — le flux tombe à zéro — comme la session laissée
    // ouverte sans personne devant.
    if (s.dejaActive && maintenant - s.derniereActivite > INACTIVITE_MS) {
      fermees.push({
        vmid: c.vmid,
        motif: `inactive depuis ${Math.round((maintenant - s.derniereActivite) / 60000)} min`,
      });
      continue;
    }

    // --- Règle 4 : durée maximale -------------------------------------------
    if (maintenant - s.creation > DUREE_MAX_MS) {
      fermees.push({ vmid: c.vmid, motif: 'durée maximale atteinte' });
    }
  }

  // Oublier les clones qui n'existent plus.
  for (const vmid of Object.keys(suivi)) if (!vivants.has(vmid)) delete suivi[vmid];

  for (const f of fermees) {
    delete suivi[String(f.vmid)];
    try {
      await fermer(f.vmid);
      console.log(`[surveillance] clone ${f.vmid} fermé : ${f.motif}`);
      if (journal) journal.ecrire({ action: 'fermeture-automatique', vmid: f.vmid, motif: f.motif, resultat: 'ok' });
    } catch (e) {
      console.warn(`[surveillance] clone ${f.vmid} : ${e.message}`);
      if (journal) journal.ecrire({ action: 'fermeture-automatique', vmid: f.vmid, motif: f.motif, resultat: 'echec', erreur: e.message });
    }
  }

  ecrire(suivi);
  return fermees;
}

/** Lance la boucle. `unref` : elle n'empêche pas le processus de s'arrêter. */
function demarrer(pve, fermer, journal) {
  const tour = () => passage(pve, fermer, journal).catch((e) =>
    console.warn(`[surveillance] ${e.message}`));
  tour();
  const minuteur = setInterval(tour, INTERVALLE_MS);
  minuteur.unref();
  console.log('[surveillance] active — inactivité '
    + `${Math.round(INACTIVITE_MS / 60000)} min, accueil ${Math.round(ACCUEIL_MS / 60000)} min `
    + `(après ${Math.round(DELAI_DEMARRAGE_MS / 60000)} min de démarrage), `
    + `durée max ${Math.round(DUREE_MAX_MS / 3600000)} h, `
    + `grâce après déconnexion ${Math.round(GRACE_DECONNEXION_MS / 60000)} min`);
  return minuteur;
}

module.exports = {
  demarrer, passage, etatDesSessions,
  signalerDeconnexion, signalerReconnexion,
  SEUIL_OCTETS_PAR_MIN, INACTIVITE_MS, ACCUEIL_MS, DUREE_MAX_MS, DELAI_DEMARRAGE_MS,
  GRACE_DECONNEXION_MS,
};
