/// <reference types="vite/client" />

declare module '*.vue' {
  import type { DefineComponent } from 'vue'
  const composant: DefineComponent<{}, {}, any>
  export default composant
}
