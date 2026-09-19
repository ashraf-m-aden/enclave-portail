<script setup lang="ts">
import { onUnmounted, ref } from 'vue'
import QRCode from 'qrcode'
import { api } from '@/api'

/**
 * Le portail tient en un seul écran, dont l'étape pilote l'affichage :
 *   connexion  → identifiants et second facteur
 *   enrolement → première connexion : poser l'application d'authentification
 *   ouverture  → la session se prépare (environ deux minutes)
 */
type Etape = 'connexion' | 'enrolement' | 'ouverture'

const etape = ref<Etape>('connexion')
const identifiant = ref('')
const motDePasse = ref('')
const code = ref('')
// Ticket de reenrolement : exige seulement apres une reinitialisation.
const ticket = ref('')
const besoinTicket = ref(false)
const reenrolement = ref(false)
const erreur = ref<string | null>(null)
const enCours = ref(false)

// Enrôlement
const secretTotp = ref('')
const qrDataUrl = ref('')

// Ouverture de session
const secondes = ref(0)
const etatOuverture = ref<'en-cours' | 'prete' | 'echec'>('en-cours')
let sondage: number | undefined

onUnmounted(() => window.clearInterval(sondage))

function reinitialiser() {
  motDePasse.value = ''
  code.value = ''
  enCours.value = false
}

async function connecter() {
  erreur.value = null
  enCours.value = true
  try {
    const r = await api.connexion(identifiant.value.trim(), motDePasse.value,
                                  code.value, ticket.value)
    if (r.etape === 'enrolement') {
      secretTotp.value = r.secret
      reenrolement.value = r.reenrolement
      qrDataUrl.value = await QRCode.toDataURL(r.uri, { width: 208, margin: 1 })
      etape.value = 'enrolement'
      code.value = ''
      enCours.value = false
      return
    }
    suivreOuverture(r.ticket)
  } catch (e) {
    const m = (e as Error).message
    erreur.value = m
    // Le serveur signale qu'un ticket est attendu : on affiche le champ.
    if (m.includes('ticket')) besoinTicket.value = true
    reinitialiser()
  }
}

async function confirmerEnrolement() {
  erreur.value = null
  enCours.value = true
  try {
    const r = await api.enrolement(identifiant.value.trim(), motDePasse.value,
                                   code.value, ticket.value)
    suivreOuverture(r.ticket)
  } catch (e) {
    erreur.value = (e as Error).message
    code.value = ''
    enCours.value = false
  }
}

/**
 * Suit l'ouverture. La création du clone prend environ deux minutes : une
 * machine neuve démarre, cloud-init y pose le compte, puis xrdp s'ouvre.
 * Mieux vaut le dire que laisser croire à un blocage.
 */
function suivreOuverture(ticket: string) {
  etape.value = 'ouverture'
  etatOuverture.value = 'en-cours'
  // Le mot de passe a servi ; il n'a plus à rester dans la page.
  motDePasse.value = ''
  code.value = ''

  sondage = window.setInterval(async () => {
    try {
      const s = await api.session(ticket)
      secondes.value = s.secondes
      etatOuverture.value = s.etat

      if (s.etat === 'prete' && s.url) {
        window.clearInterval(sondage)
        window.location.href = s.url
      } else if (s.etat === 'echec') {
        window.clearInterval(sondage)
        erreur.value = s.erreur || "l'ouverture de session a échoué"
      }
    } catch (e) {
      window.clearInterval(sondage)
      etatOuverture.value = 'echec'
      erreur.value = (e as Error).message
    }
  }, 3000)
}

function recommencer() {
  window.clearInterval(sondage)
  etape.value = 'connexion'
  erreur.value = null
  secondes.value = 0
  reinitialiser()
}
</script>

<template>
  <div class="page">
    <main class="boite">
      <img class="boite__logo" src="/logo.png" alt="INSTAD — Institut de la Statistique de Djibouti" />

      <!-- ÉTAPE 1 — Connexion -->
      <template v-if="etape === 'connexion'">
        <div class="boite__titre">
          <h1>Enclave sécurisée</h1>
          <p>Accès aux données confidentielles</p>
        </div>

        <p v-if="erreur" class="message message--erreur" role="alert">{{ erreur }}</p>

        <form class="champs" @submit.prevent="connecter">
          <div class="champ">
            <label for="ident">Identifiant</label>
            <input id="ident" v-model="identifiant" type="text" class="mono"
                   autocomplete="username" required autofocus />
          </div>

          <div class="champ">
            <label for="mdp">Mot de passe</label>
            <input id="mdp" v-model="motDePasse" type="password"
                   autocomplete="current-password" required />
          </div>

          <div class="champ">
            <label for="code">Code de vérification</label>
            <input id="code" v-model="code" type="text" class="mono code"
                   inputmode="numeric" autocomplete="one-time-code"
                   maxlength="6" placeholder="000000" />
            <p class="aide">Six chiffres, depuis votre application d'authentification.</p>
          </div>

          <!-- N'apparaît qu'après une réinitialisation : le ticket est remis
               par l'administrateur, hors bande. -->
          <div v-if="besoinTicket" class="champ">
            <label for="ticket">Ticket de réenrôlement</label>
            <input id="ticket" v-model="ticket" type="text" class="mono"
                   placeholder="XXXX-XXXX-XXXX" autocapitalize="characters" />
            <p class="aide">
              Votre second facteur a été réinitialisé. Ce ticket vous a été
              transmis par un administrateur ; il expire au bout d'une heure.
            </p>
          </div>

          <button type="submit" class="btn btn--primaire" :disabled="enCours">
            {{ enCours ? 'Vérification…' : 'Ouvrir ma session' }}
          </button>
        </form>
      </template>

      <!-- ÉTAPE 2 — Enrôlement du second facteur -->
      <template v-else-if="etape === 'enrolement'">
        <div class="boite__titre">
          <h1>{{ reenrolement ? 'Nouvelle application' : 'Première connexion' }}</h1>
          <p v-if="reenrolement">
            Votre second facteur a été réinitialisé. Associez une nouvelle
            application d'authentification.
          </p>
          <p v-else>Associez une application d'authentification à votre compte.</p>
        </div>

        <p v-if="erreur" class="message message--erreur" role="alert">{{ erreur }}</p>

        <div class="enrolement">
          <img v-if="qrDataUrl" :src="qrDataUrl" alt="QR code d'enrôlement" class="enrolement__qr" />
          <div class="enrolement__texte">
            <p>Scannez ce code avec votre application, ou saisissez la clé :</p>
            <code class="enrolement__secret">{{ secretTotp }}</code>
            <p class="aide">
              Cette clé ne sera plus affichée. Sans elle ni l'application,
              vous ne pourrez plus vous connecter.
            </p>
          </div>
        </div>

        <form class="champs" @submit.prevent="confirmerEnrolement">
          <div class="champ">
            <label for="code2">Code affiché par l'application</label>
            <input id="code2" v-model="code" type="text" class="mono code"
                   inputmode="numeric" maxlength="6" placeholder="000000" required autofocus />
          </div>

          <button type="submit" class="btn btn--primaire" :disabled="enCours">
            {{ enCours ? 'Vérification…' : 'Confirmer et ouvrir ma session' }}
          </button>
          <button type="button" class="btn btn--neutre" @click="recommencer">Annuler</button>
        </form>
      </template>

      <!-- ÉTAPE 3 — Ouverture de la session -->
      <template v-else>
        <div class="boite__titre">
          <h1>Votre session se prépare</h1>
          <p v-if="etatOuverture === 'en-cours'">
            Une machine neuve démarre pour vous. Comptez environ deux minutes.
          </p>
        </div>

        <template v-if="etatOuverture === 'en-cours'">
          <div class="progression" role="status" aria-live="polite">
            <div class="progression__barre"></div>
          </div>
          <p class="compteur">{{ secondes }} s</p>
          <p class="aide aide--centree">
            Ne fermez pas cette page. Vous serez redirigé automatiquement.
          </p>
        </template>

        <template v-else-if="etatOuverture === 'echec'">
          <p class="message message--erreur" role="alert">{{ erreur }}</p>
          <button type="button" class="btn btn--primaire" @click="recommencer">
            Réessayer
          </button>
        </template>
      </template>

      <p class="boite__note">
        Les données consultées dans cette enclave ne peuvent en sortir que sous
        forme de résultats validés. Les sessions sont enregistrées.
      </p>
    </main>
  </div>
</template>

<style scoped lang="scss">
.page {
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 100vh;
  padding: $r-5;
  background:
    radial-gradient(circle at 22% 12%, rgba(255, 255, 255, 0.07), transparent 46%),
    $djib-blue;
}

.boite {
  display: flex;
  flex-direction: column;
  gap: $r-4;
  width: 100%;
  max-width: 400px;
  padding: $r-6;
  background: $white;
  border-radius: $rayon;
  box-shadow: $ombre-h;
  // Filet rouge : le seul rappel du bandeau du logo.
  border-top: 3px solid $djib-red;

  &__logo { width: 190px; align-self: flex-start; }

  &__titre {
    display: flex;
    flex-direction: column;
    gap: 3px;

    h1 { font-size: 19px; }
    p  { font-size: 13px; color: $ink-3; }
  }

  &__note {
    font-size: 12px;
    line-height: 1.5;
    color: $ink-3;
    padding-top: $r-3;
    border-top: 1px solid $rule-soft;
  }
}

.champs {
  display: flex;
  flex-direction: column;
  gap: $r-4;

  .btn { margin-top: $r-1; }
}

.aide {
  font-size: 12px;
  color: $ink-3;
  line-height: 1.45;

  &--centree { text-align: center; }
}

// Le code de vérification se lit chiffre par chiffre : on l'espace.
.code {
  letter-spacing: 0.32em;
  font-size: 17px;
  text-align: center;
}

// ---------- enrôlement ----------

.enrolement {
  display: flex;
  gap: $r-4;
  padding: $r-4;
  background: $blue-050;
  border: 1px solid $rule;
  border-radius: $rayon-s;

  @media #{$mobile} { flex-direction: column; align-items: center; }

  &__qr {
    width: 128px;
    height: 128px;
    flex: none;
    background: $white;
    padding: 6px;
    border-radius: $rayon-s;
  }

  &__texte {
    display: flex;
    flex-direction: column;
    gap: 7px;
    font-size: 12.5px;
    min-width: 0;
  }

  &__secret {
    @include mono(12px);
    display: block;
    padding: 7px 9px;
    background: $white;
    border: 1px solid $rule;
    border-radius: $rayon-s;
    word-break: break-all;
    user-select: all;
    line-height: 1.4;
  }
}

// ---------- progression ----------

.progression {
  height: 4px;
  background: $rule-soft;
  border-radius: 999px;
  overflow: hidden;

  &__barre {
    height: 100%;
    width: 38%;
    background: $djib-blue;
    border-radius: 999px;
    animation: glisse 1.7s ease-in-out infinite;
  }
}

// Durée inconnue : une barre qui va et vient dit « ça travaille » sans
// prétendre à un pourcentage qu'on ne connaît pas.
@keyframes glisse {
  0%   { transform: translateX(-100%); }
  100% { transform: translateX(300%); }
}

.compteur {
  @include mono(13px);
  text-align: center;
  color: $ink-3;
}

@media (prefers-reduced-motion: reduce) {
  .progression__barre { animation: none; width: 100%; opacity: 0.45; }
}
</style>
