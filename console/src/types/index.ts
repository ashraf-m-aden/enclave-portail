/** Types de l'API du portail. Aucun ne porte de secret. */

export interface Chercheur {
  identifiant: string
}

/** Réponse à une tentative de connexion. */
export type Connexion =
  /** Première connexion : le second facteur doit être enrôlé. */
  | { etape: 'enrolement'; secret: string; uri: string; reenrolement: boolean }
  /** Authentifié : l'ouverture de session a démarré, suivre le ticket. */
  | { etape: 'session'; ticket: string }

/** Avancement de l'ouverture d'une session. */
export interface EtatSession {
  etat: 'en-cours' | 'prete' | 'echec'
  url: string | null
  erreur: string | null
  secondes: number
  /** VMID de SA session — dérivé de son identifiant côté serveur. */
  vmid: number | null
  /** Vrai quand le serveur a retrouvé une session au lieu d'en créer une. */
  reprise: boolean
}
