'use strict';
/**
 * =============================================================================
 *  PORTAIL — tickets de réenrôlement du second facteur
 *
 *  POURQUOI CE MÉCANISME EXISTE, ET CE QU'IL PROTÈGE VRAIMENT.
 *
 *  Le second facteur est la dernière barrière qui empêche un administrateur
 *  d'usurper un compte chercheur : il peut déjà changer un mot de passe, mais
 *  il reste bloqué devant le code. Ouvrir la réinitialisation lui donne donc
 *  un pouvoir réel — accès aux données sources et au dossier de travail du
 *  chercheur, sous son identité.
 *
 *  Un chemin de secours reste nécessaire : un téléphone perdu ne doit pas
 *  condamner un compte. Mais il doit être borné, tracé et visible :
 *
 *    - TICKET À USAGE UNIQUE ET DATÉ plutôt qu'un effacement sec. Entre la
 *      révocation et le réenrôlement, le compte n'est PAS réduit au seul mot
 *      de passe : il faut aussi le ticket, et il expire.
 *    - NOTIFICATION HORS BANDE au chercheur : c'est le contrôle le plus
 *      efficace, le seul qui détecte une réinitialisation non demandée.
 *    - DOUBLE CONTRÔLE quand deux administrateurs existent.
 *    - TRACE au journal : qui a demandé, qui a approuvé, quand.
 *
 *  Le ticket borne la fenêtre ; la notification détecte l'abus ; le double
 *  contrôle empêche l'acte unilatéral. Aucun des trois ne suffit seul.
 * =============================================================================
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const FICHIER = process.env.PORTAIL_TICKETS
  || path.join(__dirname, 'etat', 'tickets-reenrolement.json');

/** Une heure : le temps de joindre le chercheur, pas davantage. */
const VALIDITE_MS = parseInt(process.env.TICKET_VALIDITE_MS || String(60 * 60 * 1000), 10);

function lire() {
  try {
    return JSON.parse(fs.readFileSync(FICHIER, 'utf8'));
  } catch {
    return {};
  }
}

function ecrire(tickets) {
  fs.mkdirSync(path.dirname(FICHIER), { recursive: true });
  const tmp = `${FICHIER}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(tickets, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, FICHIER);
}

/**
 * Format lisible à dicter : le ticket est transmis de vive voix ou par un
 * canal hors bande, comme le mot de passe. Sans caractères ambigus.
 */
function nouvelIdentifiant() {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const octets = crypto.randomBytes(12);
  let brut = '';
  for (const o of octets) brut += alphabet[o % alphabet.length];
  return `${brut.slice(0, 4)}-${brut.slice(4, 8)}-${brut.slice(8, 12)}`;
}

/**
 * Émet un ticket pour un chercheur. L'appelant a déjà invalidé l'enrôlement.
 *
 * Un seul ticket vivant par chercheur : en émettre un nouveau remplace le
 * précédent, qui devient inutilisable.
 */
function emettre(identifiant, { demandePar, approuvePar }) {
  const tickets = lire();
  const ticket = {
    identifiant: nouvelIdentifiant(),
    emis_le: new Date().toISOString(),
    expire_le: new Date(Date.now() + VALIDITE_MS).toISOString(),
    demande_par: demandePar,
    approuve_par: approuvePar || null,
    utilise: false,
  };
  tickets[identifiant] = ticket;
  ecrire(tickets);
  return ticket;
}

/** Le ticket vivant d'un chercheur, ou null. Ne révèle jamais sa valeur. */
function etat(chercheur) {
  const t = lire()[chercheur];
  if (!t) return null;
  return {
    emis_le: t.emis_le,
    expire_le: t.expire_le,
    utilise: t.utilise,
    expire: Date.now() > Date.parse(t.expire_le),
    demande_par: t.demande_par,
    approuve_par: t.approuve_par,
  };
}

/**
 * Vérifie un ticket présenté par un chercheur.
 *
 * Comparaison à temps constant : une comparaison naïve laisserait fuir, par sa
 * durée, le nombre de caractères corrects en tête.
 */
function valide(chercheur, propose) {
  const t = lire()[chercheur];
  if (!t || t.utilise) return false;
  if (Date.now() > Date.parse(t.expire_le)) return false;

  const a = Buffer.from(String(propose || '').trim().toUpperCase());
  const b = Buffer.from(t.identifiant);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

/** Marque le ticket comme consommé. Un ticket ne sert qu'une fois. */
function consommer(chercheur) {
  const tickets = lire();
  const t = tickets[chercheur];
  if (!t) return false;
  t.utilise = true;
  t.utilise_le = new Date().toISOString();
  ecrire(tickets);
  return true;
}

module.exports = { emettre, valide, consommer, etat, VALIDITE_MS };
