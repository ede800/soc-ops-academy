import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// base relative : le site fonctionne sur https://<user>.github.io/<n'importe-quel-repo>/
export default defineConfig({
  base: './',
  plugins: [react(), tailwindcss()],
  // Le contenu pédagogique est volontairement embarqué dans le bundle (environ 180 Ko gzippés).
  build: { chunkSizeWarningLimit: 800 },
})
