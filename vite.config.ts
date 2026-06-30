import { defineConfig } from "vite";
import react from "@vitejs/plugin-react-swc";
import path from "path";
import { componentTagger } from "lovable-tagger";
import { VitePWA } from 'vite-plugin-pwa';

// https://vitejs.dev/config/
export default defineConfig(({ mode }) => ({
  server: {
    host: "::",
    port: 8080,
  },
  plugins: [
    react(),
    VitePWA({
      registerType: 'autoUpdate',
      includeAssets: ['favicon.ico', 'robots.txt'],
      manifest: {
        name: 'OWASP Shield Desk',
        short_name: 'OWASP Shield',
        description: 'Professional security scanning and vulnerability assessment platform',
        theme_color: '#000000',
        background_color: '#ffffff',
        display: 'standalone',
        scope: '/',
        start_url: '/',
        icons: [
          {
            src: '/lovable-uploads/a80f2229-ec46-4889-ae9f-a085aa1c438a.png',
            sizes: '16x16',
            type: 'image/png'
          },
          {
            src: '/lovable-uploads/20b3fd41-c296-4c90-a372-69126d1ac89e.png',
            sizes: '32x32',
            type: 'image/png'
          },
          {
            src: '/lovable-uploads/12ee01b0-b127-4c74-8ec2-b8a70717e0f9.png',
            sizes: '120x120',
            type: 'image/png'
          },
          {
            src: '/lovable-uploads/c3f572d7-721b-4a7b-80a4-31424f7e87fd.png',
            sizes: '152x152',
            type: 'image/png'
          },
          {
            src: '/lovable-uploads/cb801ee1-84cc-4239-9dc2-6e99879996c6.png',
            sizes: '180x180',
            type: 'image/png'
          },
          {
            src: '/lovable-uploads/cb801ee1-84cc-4239-9dc2-6e99879996c6.png',
            sizes: '192x192',
            type: 'image/png',
            purpose: 'any maskable'
          },
          {
            src: '/lovable-uploads/cb801ee1-84cc-4239-9dc2-6e99879996c6.png',
            sizes: '512x512',
            type: 'image/png',
            purpose: 'any maskable'
          }
        ]
      },
      workbox: {
        globPatterns: ['**/*.{js,css,html,ico,png,svg}'],
        runtimeCaching: [
          {
            urlPattern: /^https:\/\/ngjvwckatzhqpecdfeoe\.supabase\.co\/.*/i,
            handler: 'NetworkFirst',
            options: {
              cacheName: 'supabase-cache',
              expiration: {
                maxEntries: 10,
                maxAgeSeconds: 60 * 60 * 24 * 365 // 1 year
              },
              cacheableResponse: {
                statuses: [0, 200]
              }
            }
          }
        ]
      },
      devOptions: {
        enabled: true
      }
    }),
    mode === 'development' &&
    componentTagger(),
  ].filter(Boolean),
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
}));
