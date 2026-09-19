/**
 * Client de l'API du portail.
 *
 * Le cookie de session est `httpOnly` : la page ne le lit jamais. Toute
 * écriture porte l'en-tête `X-Portail`, que le serveur exige — protection
 * CSRF, en complément du `SameSite=Strict` du cookie.
 */
import type { Chercheur, Connexion, EtatSession } from '@/types'

export class ErreurApi extends Error {
  constructor(message: string, readonly statut: number) {
    super(message)
    this.name = 'ErreurApi'
  }
}

async function appeler<T>(chemin: string, options: RequestInit = {}): Promise<T> {
  const entetes: Record<string, string> = { 'X-Portail': 'enclave' }
  if (options.body) entetes['Content-Type'] = 'application/json'

  let reponse: Response
  try {
    reponse = await fetch(`/api${chemin}`, {
      credentials: 'same-origin',
      ...options,
      headers: { ...entetes, ...(options.headers as Record<string, string>) },
    })
  } catch {
    throw new ErreurApi('le portail ne répond pas', 0)
  }

  let charge: unknown
  try {
    charge = await reponse.json()
  } catch {
    throw new ErreurApi(`réponse illisible (HTTP ${reponse.status})`, reponse.status)
  }

  if (!reponse.ok) {
    throw new ErreurApi((charge as { erreur?: string }).erreur
      || `erreur HTTP ${reponse.status}`, reponse.status)
  }
  return charge as T
}

export const api = {
  connexion: (identifiant: string, motDePasse: string, code?: string) =>
    appeler<Connexion>('/connexion', {
      method: 'POST',
      body: JSON.stringify({ identifiant, motDePasse, code }),
    }),

  /** Confirme l'enrôlement du second facteur, puis ouvre la session. */
  enrolement: (identifiant: string, motDePasse: string, code: string) =>
    appeler<{ etape: 'session'; ticket: string }>('/enrolement', {
      method: 'POST',
      body: JSON.stringify({ identifiant, motDePasse, code }),
    }),

  session: (ticket: string) => appeler<EtatSession>(`/session/${ticket}`),

  moi: () => appeler<{ chercheur: Chercheur }>('/moi'),

  deconnexion: () => appeler<{ ok: true }>('/deconnexion', { method: 'POST' }),
}
