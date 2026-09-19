'use strict';
/**
 * =============================================================================
 *  PORTAIL CHERCHEUR — journal
 *
 *  Trace les connexions et les ouvertures de session. Il complète le journal
 *  de la console d'administration : ensemble, ils répondent à « qui est entré
 *  dans l'enclave, quand, et sur quel clone ».
 *
 *  RÈGLE : aucun mot de passe, aucun secret de second facteur, aucun jeton
 *  n'entre ici. Une liste de champs interdits est appliquée à chaque écriture.
 * =============================================================================
 */

const fs = require('fs');
const path = require('path');

const FICHIER = process.env.PORTAIL_JOURNAL
  || path.join(__dirname, 'etat', 'journal.jsonl');

const INTERDITS = new Set([
  'motDePasse', 'motdepasse', 'password', 'empreinte', 'passwd',
  'code', 'secret', 'uri', 'jeton', 'token', 'authToken', 'ticket',
]);

function nettoyer(valeur, profondeur = 0) {
  if (profondeur > 3 || valeur === null || typeof valeur !== 'object') return valeur;
  if (Array.isArray(valeur)) return valeur.slice(0, 20).map((v) => nettoyer(v, profondeur + 1));
  const sortie = {};
  for (const [c, v] of Object.entries(valeur)) {
    sortie[c] = INTERDITS.has(c) ? '[retiré]' : nettoyer(v, profondeur + 1);
  }
  return sortie;
}

function ecrire(evenement) {
  const ligne = JSON.stringify({ date: new Date().toISOString(), ...nettoyer(evenement) });
  fs.mkdirSync(path.dirname(FICHIER), { recursive: true });
  fs.appendFileSync(FICHIER, `${ligne}\n`, { mode: 0o600 });
}

function ok(req, action, details = {}) {
  ecrire({ action, ip: req.ip, resultat: 'ok', ...details });
}

function echec(req, action, motif, details = {}) {
  ecrire({ action, ip: req.ip, resultat: 'echec', motif, ...details });
}

function lire(limite = 200) {
  let brut;
  try { brut = fs.readFileSync(FICHIER, 'utf8'); } catch { return []; }
  return brut.split('\n').filter(Boolean).slice(-limite)
    .map((l) => { try { return JSON.parse(l); } catch { return null; } })
    .filter(Boolean).reverse();
}

module.exports = { ok, echec, lire, ecrire };
