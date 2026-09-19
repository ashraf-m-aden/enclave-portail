import { fileURLToPath, URL } from 'node:url'
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  resolve: {
    alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) },
  },
  css: {
    preprocessorOptions: {
      scss: {
        // Les variables et mixins sont disponibles dans chaque bloc <style lang="scss">
        additionalData: `@use "@/assets/scss/_variables" as *;\n@use "@/assets/scss/_mixins" as *;\n`,
      },
    },
  },
  server: {
    port: 5181,
    proxy: {
      // En développement, l'API tourne sur la passerelle.
      '/api': {
        target: process.env.VITE_API || 'http://127.0.0.1:8091',
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: 'dist',
    // La console est servie en statique par Nginx, sur le port d'administration.
    assetsDir: 'assets',
  },
})
