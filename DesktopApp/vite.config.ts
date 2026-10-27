import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  base: "./", // the built app is opened from a file, so asset paths must be relative
  plugins: [
    react(),
    tailwindcss(),
    {
      // The strict CSP <meta> in index.html is for the built app. The dev server needs inline scripts for hot reload,
      // so in dev the policy is sent by the Electron main process instead.
      name: "dev-no-meta-csp",
      apply: "serve",
      transformIndexHtml: (html: string) => html.replace(/<meta[^>]*http-equiv="Content-Security-Policy"[^>]*>/, ""),
    },
  ],
  server: { host: "127.0.0.1", port: 5173, strictPort: true },
  build: { outDir: "dist" },
});
