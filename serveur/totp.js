'use strict';
/**
 * =============================================================================
 *  PORTAIL CHERCHEUR — second facteur TOTP (RFC 6238)
 *
 *  POURQUOI ICI, ET PAS DANS GUACAMOLE. L'extension `auth-json` de Guacamole
 *  accepte un jeton signé et ouvre la session SANS passer par son propre
 *  écran de connexion : son TOTP est donc contourné, alors même que
 *  `TOTP_ENABLED` vaut « true ». Constaté sur le prototype — une session s'est
 *  ouverte sans qu'aucun second facteur ne soit demandé. Le seul endroit où il
 *  peut réellement s'appliquer au chercheur, c'est le portail.
 *
 *  On n'écrit pas de cryptographie : `createHmac` vient de la plateforme.
 *  Ce module ne fait qu'assembler le format décrit par la RFC.
 * =============================================================================
 */

const crypto = require('crypto');

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const PAS_S = 30;       // fenêtre d'un code, en secondes
const CHIFFRES = 6;
// Une fenêtre de part et d'autre : tolère une horloge décalée d'environ
// trente secondes, sans ouvrir une fenêtre de rejeu trop large.
const TOLERANCE = 1;

function encoderBase32(octets) {
  let bits = 0;
  let valeur = 0;
  let sortie = '';
  for (const o of octets) {
    valeur = (valeur << 8) | o;
    bits += 8;
    while (bits >= 5) {
      sortie += ALPHABET[(valeur >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) sortie += ALPHABET[(valeur << (5 - bits)) & 31];
  return sortie;
}

function decoderBase32(chaine) {
  let bits = 0;
  let valeur = 0;
  const octets = [];
  for (const c of chaine.toUpperCase().replace(/=+$/, '')) {
    const i = ALPHABET.indexOf(c);
    if (i === -1) throw new Error('secret TOTP invalide');
    valeur = (valeur << 5) | i;
    bits += 5;
    if (bits >= 8) {
      octets.push((valeur >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(octets);
}

/** Secret de 160 bits, la longueur recommandée pour HMAC-SHA1. */
function nouveauSecret() {
  return encoderBase32(crypto.randomBytes(20));
}

/** Code attendu pour un compteur donné (RFC 4226, « truncation » dynamique). */
function codePourCompteur(secret, compteur) {
  const cle = decoderBase32(secret);
  const tampon = Buffer.alloc(8);
  tampon.writeBigUInt64BE(BigInt(compteur));

  const mac = crypto.createHmac('sha1', cle).update(tampon).digest();
  const decalage = mac[mac.length - 1] & 0x0f;
  const binaire = ((mac[decalage] & 0x7f) << 24)
                | ((mac[decalage + 1] & 0xff) << 16)
                | ((mac[decalage + 2] & 0xff) << 8)
                | (mac[decalage + 3] & 0xff);

  return String(binaire % 10 ** CHIFFRES).padStart(CHIFFRES, '0');
}

/**
 * Vérifie un code.
 *
 * La comparaison est à temps constant : une comparaison naïve laisserait
 * fuir, par sa durée, le nombre de chiffres corrects en tête.
 *
 * @returns {number|null} le compteur validé, ou null. L'appelant DOIT
 *   enregistrer ce compteur et refuser qu'il serve deux fois : sans cela, un
 *   code intercepté reste utilisable pendant toute sa fenêtre.
 */
function verifier(secret, code, compteurDejaUtilise = null) {
  if (typeof code !== 'string' || !/^\d{6}$/.test(code.trim())) return null;
  const propose = Buffer.from(code.trim());
  const maintenant = Math.floor(Date.now() / 1000 / PAS_S);

  for (let d = -TOLERANCE; d <= TOLERANCE; d++) {
    const compteur = maintenant + d;
    if (compteurDejaUtilise !== null && compteur <= compteurDejaUtilise) continue;

    const attendu = Buffer.from(codePourCompteur(secret, compteur));
    if (attendu.length === propose.length && crypto.timingSafeEqual(attendu, propose)) {
      return compteur;
    }
  }
  return null;
}

/** URI `otpauth://` à présenter en QR code lors de l'enrôlement. */
function uriEnrolement(secret, identifiant, emetteur = 'Enclave INSTAD') {
  const e = encodeURIComponent(emetteur);
  const c = encodeURIComponent(`${emetteur}:${identifiant}`);
  return `otpauth://totp/${c}?secret=${secret}&issuer=${e}`
       + `&algorithm=SHA1&digits=${CHIFFRES}&period=${PAS_S}`;
}

module.exports = {
  nouveauSecret, verifier, uriEnrolement, codePourCompteur,
  encoderBase32, decoderBase32, PAS_S, CHIFFRES,
};
