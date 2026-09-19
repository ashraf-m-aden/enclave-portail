import { createRouter, createWebHistory } from 'vue-router'

/**
 * Le portail tient en un seul écran : l'état de la connexion pilote ce qui
 * s'affiche. Pas de navigation, donc pas de barre de menu — un chercheur vient
 * pour entrer dans l'enclave, rien d'autre.
 */
export const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', name: 'accueil', component: () => import('@/views/AccueilVue.vue') },
    { path: '/:chemin(.*)*', redirect: '/' },
  ],
})
